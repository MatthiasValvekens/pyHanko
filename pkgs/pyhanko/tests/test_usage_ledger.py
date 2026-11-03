from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.reader import RawPdfPath
from pyhanko.sign.diff_analysis import ModificationLevel, ReferenceUpdate
from pyhanko.sign.diff_analysis.rules_api import Context, RelativeContext
from pyhanko.sign.diff_analysis.usage_ledger import _GraphLedger

from .test_usage_graph import _build, _obj, _outline_document, _ref_at

LEVEL = ModificationLevel.FORM_FILLING


def _path_update(resolver, ref, *path):
    return ReferenceUpdate(
        ref, Context.from_absolute(resolver, RawPdfPath(*path))
    )


def _tracked_ledger(resolver, *refs) -> _GraphLedger:
    ledger = _GraphLedger(resolver)
    ledger.track(refs)
    return ledger


def _twice_used_object(w, pages):
    w.root['/Foo'] = w.add_object(_obj({'/V': generic.NumberObject(1)}))
    w.root['/Bar'] = w.root.raw_get('/Foo')


def test_untracked_refs_are_explained_on_first_approval():
    resolver = _build(_twice_used_object)
    ledger = _tracked_ledger(resolver)
    stranger = generic.Reference(99, 0)
    assert ledger.ingest(LEVEL, ReferenceUpdate(stranger)) == LEVEL
    assert ledger.remaining_report() == ''


def test_level_is_the_highest_level_seen_for_a_ref():
    resolver = _build(_twice_used_object)
    ref = _ref_at(resolver, '/Root', '/Foo')
    ledger = _tracked_ledger(resolver, ref)
    foo, bar = ('/Root', '/Foo'), ('/Root', '/Bar')
    assert ledger.ingest(LEVEL, _path_update(resolver, ref, *foo)) is None
    assert (
        ledger.ingest(
            ModificationLevel.ANNOTATIONS, _path_update(resolver, ref, *bar)
        )
        == ModificationLevel.ANNOTATIONS
    )
    # approvals after the fact don't lower the level
    assert (
        ledger.ingest(ModificationLevel.LTA_UPDATES, ReferenceUpdate(ref))
        == ModificationLevel.ANNOTATIONS
    )


def test_report_shows_remaining_paths():
    resolver = _build(_twice_used_object)
    ref = _ref_at(resolver, '/Root', '/Foo')
    ledger = _tracked_ledger(resolver, ref)
    assert '.Root.Foo (2 paths)' in ledger.remaining_report() or (
        '.Root.Bar (1 path)' in ledger.remaining_report()
    )
    ledger.ingest(LEVEL, _path_update(resolver, ref, '/Root', '/Foo'))
    report = ledger.remaining_report()
    assert '.Root.Bar (1 path)' in report
    assert report.startswith(f' - {ref!r} is also used in')
    ledger.ingest(LEVEL, _path_update(resolver, ref, '/Root', '/Bar'))
    assert ledger.remaining_report() == ''


def test_cyclic_usages_are_only_cleared_by_relative_or_blanket_approval():
    resolver = _build(_outline_document)
    item = _ref_at(resolver, '/Root', '/Outlines', '/First')
    outlines = _ref_at(resolver, '/Root', '/Outlines')
    first_path = ('/Root', '/Outlines', '/First')

    ledger = _tracked_ledger(resolver, item)
    assert (
        ledger.ingest(LEVEL, _path_update(resolver, item, *first_path)) is None
    )
    report = ledger.remaining_report()
    assert 'at least 2^32 paths, via a reference cycle' in report
    relative = ReferenceUpdate(
        item, RelativeContext(outlines, RawPdfPath('/First'))
    )
    assert ledger.ingest(LEVEL, relative) is None
    other = ReferenceUpdate(item, RelativeContext(item, RawPdfPath('/Prev')))
    assert ledger.ingest(LEVEL, other) is None  # not a usage of /First's item

    ledger = _tracked_ledger(resolver, item)
    assert ledger.ingest(LEVEL, ReferenceUpdate(item)) == LEVEL


def test_report_abbreviates_long_paths():
    def populate(w, pages):
        current = w.add_object(_obj({'/Leaf': generic.NumberObject(0)}))
        for _ in range(300):
            current = w.add_object(_obj({'/A': current}))
        w.root['/Chain'] = current

    resolver = _build(populate)
    leaf = _ref_at(resolver, '/Root', '/Chain', *(['/A'] * 300))
    report = _tracked_ledger(resolver, leaf).remaining_report()
    assert report.startswith(f' - {leaf!r} is also used in .Root.Chain.A')
    assert '.A....A.A' in report
    assert len(report) < 400


def test_report_clips_long_descriptions():
    def populate(w, pages):
        w.root['/' + 'K' * 5000] = w.add_object(_obj({}))

    resolver = _build(populate)
    ref = _ref_at(resolver, '/Root', '/' + 'K' * 5000)
    report = _tracked_ledger(resolver, ref).remaining_report()
    assert len(report) < 600
    assert '...' in report


def test_report_limits_groups_and_refs():
    def populate(w, pages):
        for ix in range(25):
            shared = w.add_object(_obj({}))
            for key in range(8):
                w.root[f'/C{ix}_{key}'] = shared

    resolver = _build(populate)
    refs = [_ref_at(resolver, '/Root', f'/C{ix}_0') for ix in range(25)]
    report = _tracked_ledger(resolver, *refs).remaining_report()
    lines = report.splitlines()
    assert len(lines) == 21
    assert all('... and 3 more' in line for line in lines[:20])
    assert lines[-1].endswith('... and 5 more objects with unapproved usages.')


def test_report_lists_trailer_usages():
    def populate(w, pages):
        w.root['/Foo'] = w.root.raw_get('/Pages')

    resolver = _build(populate)
    report = _tracked_ledger(resolver, resolver.root_ref).remaining_report()
    assert '.Root (1 path)' in report
