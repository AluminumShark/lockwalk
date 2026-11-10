"""Holds references to trading_app functions the way user code does."""

from harness_apps import trading_app
from harness_apps.trading_app import check_access, place_order

HELD = [trading_app.place_order]  # a container: the reference scan does not reach it
ALIAS = trading_app.place_order
DIRECT = place_order
DOOR_ALIAS = check_access
