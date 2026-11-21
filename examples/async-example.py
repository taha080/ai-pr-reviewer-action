"""Deliberately blocking async code — exercises ASC101–ASC105.

Used to dogfood the Python async rules on a real PR.
Do not copy this style.
"""

import asyncio
import time


async def fetch_user(user_id: int) -> dict:
    """Fetch a user by id."""
    await asyncio.sleep(0.1)
    return {"id": user_id}


async def slow_handler() -> None:
    """Handle a request, slowly."""
    await asyncio.sleep(0)
    time.sleep(5)


async def caller() -> None:
    """Call fetch_user, once properly and once not."""
    fetch_user(1)
    await fetch_user(2)


async def not_really_async() -> int:
    """Return a constant, with no await anywhere."""
    return 42


async def nested_loop() -> None:
    """Run a coroutine through a loop that is already running."""
    await asyncio.sleep(0)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(fetch_user(1))


async def fire_and_forget() -> None:
    """Start a task and drop the handle."""
    await asyncio.sleep(0)
    asyncio.create_task(fetch_user(3))
