from datetime import datetime
from dateutil.relativedelta import relativedelta
start_date = datetime.now()
one_year = start_date - relativedelta(months=6)

date_str = one_year.strftime("%Y-%m-%d")

print(start_date)
print(date_str)