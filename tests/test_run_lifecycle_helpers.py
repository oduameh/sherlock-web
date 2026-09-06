"""Helpers that keep a cancelled or crashed run from leaking work."""

import asyncio

from recon import pipeline, router


def test_children_are_cancelled_when_the_run_task_ends():
    """Cancelling a run used to cancel only the child it was awaiting; the
    other engine tasks kept scanning as orphans."""
    async def scenario():
        children = pipeline._Children()

        async def sleeper():
            await asyncio.sleep(30)

        async def run():
            children.spawn(sleeper()); children.spawn(sleeper()); children.spawn(sleeper())
            asyncio.current_task().add_done_callback(lambda _t: children.cancel_pending())
            await asyncio.sleep(30)

        task = asyncio.create_task(run())
        await asyncio.sleep(0.01)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        await asyncio.sleep(0.01)
        return [t.cancelled() for t in children.tasks]

    assert asyncio.run(scenario()) == [True, True, True]


def test_router_finish_is_idempotent():
    calls = []

    class Store:
        def record_batch(self, buffered):
            calls.append(len(buffered))

        def record_proxy(self, *a):
            pass

        def open_circuits(self, *a, **k):
            return set()

    class Pool:
        configured = False

    r = router.RunRouter(":memory:", emit=lambda *a: None, proxy_pool=Pool())
    r.store = Store()
    r.disabled = False
    r._buffer = {("site", "sherlock"): [{"ok": True}]}
    r.finish()
    r.finish()                       # done-callback + explicit call
    assert calls == [1], "observations must be flushed exactly once"
