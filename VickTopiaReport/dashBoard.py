from dash import Dash, dash_table
from dash.dependencies import Input, Output
import pandas as pd

df = pd.read_csv('C:\\dev\\git\\VickTopiaReport\\reports\\EndpointsGroup.csv')
#df1 = df['group']
#df1.groupby
#df.agg['group']
#df1.agg(['sum', 'min'])
group_names = df.group.unique()
#df1 = df.groupby(['group']).unique()
for g in group_names:
    print(g)

df = pd.DataFrame (group_names, columns = ['group'])

df = pd.read_csv('reports\Vulnerabilities.csv')
df = df[['asset','cve']]

df[' index'] = range(1, len(df) + 1)

app = Dash(__name__)

PAGE_SIZE = 15

app.layout = dash_table.DataTable(
    id='datatable-paging',
    columns=[
        {"name": i, "id": i} for i in sorted(df.columns)
    ],
    page_current=0,
    page_size=PAGE_SIZE,
    page_action='custom'
)


@app.callback(
    Output('datatable-paging', 'data'),
    Input('datatable-paging', "page_current"),
    Input('datatable-paging', "page_size"))
def update_table(page_current,page_size):
    return df.iloc[
        page_current*page_size:(page_current+ 1)*page_size
    ].to_dict('records')


if __name__ == '__main__':
    app.run_server(debug=True)