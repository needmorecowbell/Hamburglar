import requests
import lxml.html as lh
import pandas as pd
import sqlalchemy as db
import re


# magic_sig_scraper scrapes the dynamic list of magic numbers from wikipedia, storing it in a database.
# this database can then be used to supplement hamburglar.py 
# It does not need to be updated very regularly, but you can set this on a cron job
url='https://en.wikipedia.org/wiki/List_of_file_signatures'

#Create a handle, page, to handle the contents of the website
page = requests.get(url)

#Store the contents of the website under doc
doc = lh.fromstring(page.content)

#Parse data that are stored between <tr>..</tr> of HTML
tr_elements = doc.xpath('//tr')

#Create empty list
col = []
i = 0

for t in tr_elements[0]:
    i += 1
    name = t.text_content().strip()
    print(i, name)
    if name != "":
        col.append((name, []))

for j in range(1, len(tr_elements)):
    T = tr_elements[j]
    i = 0

    for t in T.iterchildren():
        data = t.text_content().strip()

        if i > 0:
            try:
                data = int(data)
            except:
                pass

        col[i][1].append(data)

        i += 1

Dict = {title:column for (title, column) in col}
df = pd.DataFrame(dict([(k, pd.Series(v)) for k, v in Dict.items()]))

engine = db.create_engine('mysql+pymysql://hamman:deadbeef@localhost/fileSign')
conn = engine.connect()

df.to_sql("signatures", engine, if_exists='replace')
db_string = engine.execute("SELECT `Hex signature` FROM `signatures` WHERE signatures.index=0").fetchall()

print(db_string)