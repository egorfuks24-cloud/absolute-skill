#!/usr/bin/env python3
"""Read-only design contract readiness and measured-value checks; not a visual judge."""
import argparse
import hashlib
import json
import struct
import zlib
from pathlib import Path
from urllib.parse import urlsplit, unquote


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def image_size(data):
    """Validate image structure and extract size, not pixel content/authenticity."""
    if data.startswith(b'\x89PNG\r\n\x1a\n'):
        pos = 8
        size = None
        has_data = False
        while pos + 12 <= len(data):
            length = struct.unpack('>I', data[pos:pos+4])[0]
            end = pos + 12 + length
            if end > len(data):
                break
            kind = data[pos+4:pos+8]
            payload = data[pos+8:pos+8+length]
            if zlib.crc32(kind + payload) & 0xffffffff != struct.unpack('>I', data[end-4:end])[0]:
                raise ValueError('Invalid PNG chunk CRC')
            if kind == b'IHDR' and pos == 8 and length == 13:
                size = struct.unpack('>II', payload[:8])
            if kind == b'IDAT' and length:
                has_data = True
            if kind == b'IEND' and length == 0 and end == len(data) and size and has_data:
                return size
            pos = end
        raise ValueError('Incomplete PNG image')
    if data.startswith(b'\xff\xd8\xff') and data.endswith(b'\xff\xd9'):
        pos = 2
        while pos + 4 <= len(data):
            if data[pos] != 255:
                break
            while pos < len(data) and data[pos] == 255:
                pos += 1
            marker = data[pos]; pos += 1
            if marker in (0xd8, 0xd9) or 0xd0 <= marker <= 0xd7:
                continue
            length = int.from_bytes(data[pos:pos+2], 'big')
            if length < 2 or pos + length > len(data):
                break
            if marker in (0xc0, 0xc1, 0xc2) and length >= 8:
                height, width = struct.unpack('>HH', data[pos+3:pos+7])
                if b'\xff\xda' not in data[pos+length:]:
                    break
                return width, height
            pos += length
        raise ValueError('Incomplete JPEG image')
    if data[:4] == b'RIFF' and data[8:12] == b'WEBP' and len(data) >= 30:
        if int.from_bytes(data[4:8], 'little') + 8 != len(data):
            raise ValueError('Incomplete WebP image')
        kind = data[12:16]
        if kind == b'VP8X':
            return 1 + int.from_bytes(data[24:27], 'little'), 1 + int.from_bytes(data[27:30], 'little')
        if kind == b'VP8L' and data[20] == 0x2f:
            bits = int.from_bytes(data[21:25], 'little')
            return (bits & 0x3fff) + 1, ((bits >> 14) & 0x3fff) + 1
        if kind == b'VP8 ' and data[23:26] == b'\x9d\x01\x2a':
            return int.from_bytes(data[26:28], 'little') & 0x3fff, int.from_bytes(data[28:30], 'little') & 0x3fff
    raise ValueError('Expected complete PNG/JPEG/WebP image, not a text citation')


def check(project, stage, allow_legacy_fixture=False):
    root = project.resolve()
    errors = []

    def fail(message):
        errors.append(message)

    def local(value):
        if not isinstance(value, str) or not value or Path(value).is_absolute():
            raise ValueError('Expected a nonempty project-relative file path')
        p = (root / value).resolve()
        try:
            p.relative_to(root)
        except ValueError:
            raise ValueError('Path escapes project: ' + value)
        if not p.is_file():
            raise ValueError('Missing file: ' + value)
        return p

    def hashed(entry, label):
        if not isinstance(entry, dict):
            fail(label + ': expected object')
            return
        try:
            p = local(entry.get('path'))
            if entry.get('sha256') != sha(p):
                fail(label + ': content hash mismatch: ' + str(entry.get('path')))
        except (OSError, ValueError) as exc:
            fail(label + ': ' + str(exc))

    cpath = local('.absolute/design-contract.json')
    c = json.loads(cpath.read_text())
    if not isinstance(c, dict):
        raise ValueError('Contract must be an object')
    if c.get('schema_version') not in (1, 2):
        fail('Unsupported schema_version')
    if c.get('schema_version') == 1 and c.get('scope') == 'test-fixture' and not allow_legacy_fixture:
        fail('Legacy fixture requires explicit compatibility mode; new simulations use schema_version=2')
    visual_required = c.get('schema_version') == 2 or c.get('scope') == 'product'
    # Old test fixtures remain readable; real products must carry provenance.
    if c.get('schema_version') == 2 or c.get('scope') == 'product':
        registry = json.loads((Path(__file__).resolve().parents[1] / 'references/design-source-registry.json').read_text())
        sources = {item['id']: item for item in registry['sources']}
        covered = set()
        provenance = c.get('design_provenance')
        if not isinstance(provenance, list) or not provenance:
            fail('Missing design_provenance: default model design is not a source')
            provenance = []
        for entry in provenance:
            if not isinstance(entry, dict):
                fail('Design provenance must be an object')
                continue
            kind = entry.get('kind')
            if kind == 'registry':
                ident = entry.get('source_id')
                source = sources.get(ident) if isinstance(ident, str) else None
                try:
                    if not isinstance(entry.get('url'), str):
                        raise ValueError('Source URL must be text')
                    url = urlsplit(entry.get('url', ''))
                    if (source is None or url.scheme != 'https' or url.username is not None
                            or url.password is not None or url.port not in (None, 443)
                            or url.hostname not in source['allowed_hosts']):
                        fail('Design source outside approved registry')
                    elif source.get('path_prefix'):
                        prefix = source['path_prefix']
                        path = unquote(url.path)
                        if (path != prefix and not path.startswith(prefix + '/')) or any(x in ('.', '..') for x in path.split('/')):
                            fail('Design source outside approved repository path')
                    if not isinstance(entry.get('element'), str) or not entry['element'].strip():
                        fail('Missing specific source element')
                except (ValueError, TypeError):
                    fail('Malformed design source URL')
            elif kind == 'bundled':
                if entry.get('source_id') not in registry['bundled_design_skills']:
                    fail('Unknown bundled design source')
                locator = entry.get('element')
                if not isinstance(locator, str) or not locator.strip():
                    fail('Missing exact bundled material/section')
            elif kind in ('existing-approved', 'user-exception'):
                try:
                    quote = entry.get('approval_quote')
                    if not isinstance(quote, str) or not quote.strip() or quote not in local(entry.get('approval_record')).read_text():
                        fail('Missing explicit approval for existing design/source exception')
                except (ValueError, OSError) as exc:
                    fail(str(exc))
            else:
                fail('Invalid design provenance kind')
            if not isinstance(entry.get('detail'), str) or not entry['detail'].strip():
                fail('Missing borrowed features and adaptation')
            hashed(entry.get('evidence'), 'Design source evidence')
            applies = entry.get('applies_to')
            dimensions = {'composition', 'responsive', 'typography', 'colors', 'spacing', 'components', 'motion', 'content'}
            if not isinstance(applies, list) or not applies or any(not isinstance(x, str) or x not in dimensions for x in applies):
                fail('Invalid provenance applies_to')
            else:
                covered.update(applies)
        for dimension in ('composition', 'responsive', 'typography', 'colors', 'spacing', 'components', 'motion', 'content'):
            if dimension not in covered:
                fail('Untraceable design rule: ' + dimension)
    def captured_image(entry, label):
        hashed(entry, label)
        try:
            data = local(entry.get('path')).read_bytes()
            size = image_size(data)
            if min(size) <= 0:
                raise ValueError('Image dimensions must be positive')
            return size
        except (OSError, ValueError, AttributeError, TypeError) as exc:
            fail(label + ': invalid image evidence: ' + str(exc))
    if visual_required:
        basis = c.get('visual_basis')
        if not isinstance(basis, list) or not basis:
            fail('Missing visual_basis: generic style or component citation cannot approve a composition')
            basis = []
        provenance = c.get('design_provenance', [])
        if not isinstance(provenance, list):
            provenance = []
        for item in basis:
            if not isinstance(item, dict):
                fail('Visual basis must be an object')
                continue
            index = item.get('provenance_index')
            source = provenance[index] if type(index) is int and 0 <= index < len(provenance) else None
            if not isinstance(source, dict) or not isinstance(source.get('applies_to'), list) or 'composition' not in source['applies_to']:
                fail('Visual basis must identify composition provenance')
            elif source.get('kind') == 'registry':
                if not isinstance(source.get('source_id'), str) or source['source_id'] not in {'astryx', 'arloui', 'posts-design', 'recent-design', 'inspora', '21st'}:
                    fail('Icon/font/effect library is not a composition reference')
            elif source.get('kind') not in ('existing-approved', 'user-exception'):
                fail('Generic bundled guidance is not a primary composition reference; use an actual approved mockup or concrete visual source')
            if item.get('material_type') not in ('specific-composition', 'approved-mockup', 'existing-interface'):
                fail('Visual basis must be a specific composition, not a style/palette/component recipe')
            captured_image(item.get('capture'), 'Visual basis capture')
            hashed(item.get('inspection'), 'Visual basis inspection')
            features = item.get('borrowed_features')
            if not isinstance(features, list) or len(features) < 2 or any(not isinstance(x, str) or not x.strip() for x in features):
                fail('Record concrete visual features actually borrowed')
            if not isinstance(item.get('adaptation'), str) or not item['adaptation'].strip():
                fail('Missing visual adaptation to the brief')
    if c.get('status') != 'approved':
        fail('Design has not been selected')
    if c.get('scope') not in ('product', 'test-fixture'):
        fail('Invalid scope')
    if not isinstance(c.get('selected_option'), str) or not c['selected_option'].strip():
        fail('Missing selected_option')
    approval = c.get('approval')
    if not isinstance(approval, dict):
        fail('Missing approval record')
    else:
        origin = approval.get('origin')
        if origin not in ('user', 'test-harness'):
            fail('Invalid approval origin')
        if c.get('scope') == 'product' and origin != 'user':
            fail('Test approval cannot approve a product')
        quote = approval.get('quote')
        if not isinstance(quote, str) or not quote.strip():
            fail('Missing approval quote')
        else:
            try:
                if quote not in local(approval.get('record')).read_text():
                    fail('Approval quote is absent from its record')
            except (OSError, ValueError) as exc:
                fail(str(exc))
    artifacts = c.get('artifacts')
    if not isinstance(artifacts, list) or not artifacts:
        fail('Missing agreed artifacts')
        artifacts = []
    roles = set()
    for entry in artifacts:
        hashed(entry, 'Artifact')
        if isinstance(entry, dict) and isinstance(entry.get('role'), str):
            roles.add(entry['role'])
    if not {'content', 'tokens', 'reference'} <= roles:
        fail('Required artifact roles: content, tokens, reference')
    rules = c.get('rules')
    for name in ('composition', 'responsive', 'typography', 'colors', 'spacing', 'components', 'motion', 'content'):
        if not isinstance(rules, dict) or not isinstance(rules.get(name), str) or not rules[name].strip():
            fail('Missing concrete rule or not-applicable reason: ' + name)
    checks = c.get('checks')
    if not isinstance(checks, list) or not checks:
        fail('Missing observable checks')
        checks = []
    ids = set()
    for item in checks:
        if not isinstance(item, dict):
            fail('Check must be an object')
            continue
        ident = item.get('id')
        if not isinstance(ident, str) or not ident or ident in ids:
            fail('Missing/duplicate check ID')
        else:
            ids.add(ident)
        if item.get('kind') not in ('text', 'css'):
            fail('Check kind must be text or css')
        for key in ('selector', 'state', 'expected'):
            if not isinstance(item.get(key), str) or not item[key].strip():
                fail('Missing check field: ' + key)
        if item.get('kind') == 'css' and not isinstance(item.get('property'), str):
            fail('CSS check needs property')
        viewport = item.get('viewport')
        if not isinstance(viewport, dict) or any(type(viewport.get(k)) is not int or viewport[k] <= 0 for k in ('width', 'height')):
            fail('Check needs positive viewport width/height')
    if stage == 'verify' and not errors:
        observation = json.loads(local('.absolute/observed-design.json').read_text())
        if not isinstance(observation, dict):
            raise ValueError('Observation must be an object')
        if observation.get('contract_sha256') != sha(cpath):
            fail('Observations are stale for this contract')
        measured = observation.get('checks')
        if not isinstance(measured, list):
            fail('Missing observations')
            measured = []
        actual = {}
        for entry in measured:
            if not isinstance(entry, dict) or not isinstance(entry.get('id'), str):
                fail('Malformed observation')
                continue
            ident = entry['id']
            if ident in actual:
                fail('Duplicate observed ID: ' + ident)
            actual[ident] = entry.get('actual')
        if set(actual) != ids:
            fail('Observed check IDs differ from contract')
        for item in checks:
            if actual.get(item['id']) != item['expected']:
                fail('Observed value differs: ' + item['id'])
        evidence = observation.get('evidence')
        if not isinstance(evidence, list) or not evidence:
            fail('Missing captured evidence')
        else:
            for entry in evidence:
                hashed(entry, 'Evidence')
        if visual_required:
            try:
                review = json.loads(local('.absolute/visual-review.json').read_text())
            except (OSError, ValueError) as exc:
                fail('Missing or malformed visual comparison: ' + str(exc))
                review = {}
            if not isinstance(review, dict) or review.get('contract_sha256') != sha(cpath):
                fail('Missing or stale separate visual comparison')
                review = {}
            if review.get('status') != 'reviewed':
                fail('Visual comparison not reviewed; functional PASS is not design acceptance')
            comparisons = review.get('comparisons', [])
            if not isinstance(comparisons, list):
                comparisons = []
            reference_paths = {x['path'] for x in artifacts if isinstance(x, dict) and x.get('role') == 'reference' and isinstance(x.get('path'), str)}
            observed_paths = {x['path'] for x in evidence if isinstance(x, dict) and isinstance(x.get('path'), str)} if isinstance(evidence, list) else set()
            wide = narrow = False
            for item in comparisons:
                if not isinstance(item, dict):
                    fail('Visual comparison must be an object')
                    continue
                ref, actual = item.get('reference'), item.get('actual')
                ref_size = captured_image(ref, 'Selected option reference')
                actual_size = captured_image(actual, 'Actual implementation capture')
                if not isinstance(ref, dict) or not isinstance(ref.get('path'), str) or ref['path'] not in reference_paths:
                    fail('Visual comparison reference is not a selected artifact')
                if not isinstance(actual, dict) or not isinstance(actual.get('path'), str) or actual['path'] not in observed_paths:
                    fail('Visual comparison actual is not measured evidence')
                if isinstance(ref, dict) and isinstance(actual, dict) and ref.get('path') == actual.get('path'):
                    fail('Option capture cannot serve as implementation capture')
                width = item.get('viewport', {}).get('width') if isinstance(item.get('viewport'), dict) else None
                height = item.get('viewport', {}).get('height') if isinstance(item.get('viewport'), dict) else None
                if type(width) is not int or width <= 0 or type(height) is not int or height <= 0:
                    fail('Visual comparison needs positive viewport width/height')
                if ref_size != (width, height) or actual_size != (width, height):
                    fail('Capture dimensions differ from declared comparison viewport')
                if type(width) is int:
                    wide |= width >= 1000
                    narrow |= width <= 600 and width > 0
                if not isinstance(item.get('retained_features'), list) or not item['retained_features'] or any(not isinstance(x, str) or not x.strip() for x in item['retained_features']):
                    fail('Missing observed retained visual features')
                if not isinstance(item.get('deviations'), list):
                    fail('Missing explicit visual deviations list')
                elif any(not isinstance(x, dict) or x.get('status') not in ('fixed', 'explicitly-selected') or not isinstance(x.get('reason'), str) or not x['reason'].strip() for x in item['deviations']):
                    fail('Unresolved or unexplained visual deviation; do not approve a drift by rewriting observations')
                else:
                    for deviation in item['deviations']:
                        if deviation.get('status') == 'explicitly-selected':
                            try:
                                quote = deviation.get('approval_quote')
                                if not isinstance(quote, str) or not quote.strip() or quote not in local(deviation.get('approval_record')).read_text():
                                    fail('Visual deviation needs recorded explicit selection')
                            except (ValueError, OSError) as exc:
                                fail(str(exc))
            if not wide or not narrow:
                fail('Visual comparison needs wide and narrow selected-versus-actual captures')
            if c.get('scope') == 'test-fixture' and review.get('aesthetic_acceptance') != 'synthetic-only':
                fail('Simulated choice is not human aesthetic acceptance')
    if c.get('product_concept_required') is True:
        import importlib.util
        spec = importlib.util.spec_from_file_location('absolute_concept_check', Path(__file__).with_name('concept_check.py'))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for error in module.check(project, 'selected')['errors']:
            fail('Product concept: ' + error)
    if visual_required:
        import importlib.util
        spec = importlib.util.spec_from_file_location('absolute_quality_check', Path(__file__).with_name('quality_check.py'))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        quality = module.check(project)
        for error in quality['errors']:
            fail('Content/asset quality: ' + error)
    return {'stage': stage, 'passed': not errors, 'errors': errors,
            'scope': c.get('scope'), 'approval_authenticity': 'not verified by script',
            'visual_review': 'required separately; not performed by this checker'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--project', type=Path, required=True)
    p.add_argument('--stage', choices=('ready', 'verify'), required=True)
    p.add_argument('--allow-legacy-fixture', action='store_true', help='Compatibility only: old v1 test fixtures, not new simulations/products')
    args = p.parse_args()
    try:
        result = check(args.project, args.stage, args.allow_legacy_fixture)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        result = {'stage': args.stage, 'passed': False, 'errors': [str(exc)]}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
