# date_of_birth — keygen
#
# Generates all valid date inputs for today's date.
#
# The binary computes: localtime(time(NULL) - mktime(birth_date))
# and checks the resulting struct tm against three conditions:
#   1. tm_mday  in {30, 31}       (difference lands on 30th or 31st)
#   2. tm_mon   == 11             (December in epoch time, 0-indexed)
#   3. (tm_year - 70) & 0xFF == 0x7F   (signed byte overflow in year check)
#
# Condition 3 is satisfied when the year difference is 127 + k*256 for k >= 0.
# A birth date of (today + 1 day) in year (today.year - 128*k) produces a
# difference of exactly (128k years - 1 day), which localtime() maps to
# December 31 of year (1970 + 127 + (k-1)*256) — satisfying all three.
#
# Usage:
#   python3 keygen.py          # prints one random valid date
#   python3 keygen.py --all    # prints all valid dates

from datetime import date, timedelta
import random
import sys

keys = []
today = date.today()
i = 0

while True:
    year_diff = 128 + i * 256       # 128, 384, 640, ... (difference in years)
    if year_diff >= today.year:     # can't go before year 1
        break
    # Birth date = (today + 1 day) but year_diff years earlier.
    # The +1 day shift makes the difference (year_diff years - 1 day),
    # which localtime() maps to Dec 31 instead of rolling over to Jan 1.
    birth = date(
        year  = today.year - year_diff,
        month = today.month,
        day   = today.day
    ) + timedelta(days=1)
    keys.append(birth)
    i += 1

if not keys:
    print("No valid keys for today's date.")
    raise SystemExit(1)

if "--all" in sys.argv:
    for k in keys:
        print("{}/{}/{}".format(k.month, k.day, k.year))
else:
    key = keys[random.randint(0, len(keys) - 1)]
    print("{}/{}/{}".format(key.month, key.day, key.year))
