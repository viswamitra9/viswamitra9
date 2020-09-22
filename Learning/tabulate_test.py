import datetime
now = datetime.datetime.now()
th = ""
for _ in range(0, 6):
   now = now.replace(day=1) - datetime.timedelta(days=1)
   th += "<th> {}_{} </th> ".format(now.month, now.year)
