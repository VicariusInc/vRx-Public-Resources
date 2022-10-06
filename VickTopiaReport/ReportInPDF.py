import fpdf
from fpdf import FPDF
import time
import pandas as pd
import matplotlib.pyplot as plt
import imgkit
import dataframe_image as dfi
import sqlite3

from sqlalchemy import column

def generate_matplotlib_stackbars(df, filename):
    
    # Create subplot and bar
    fig, ax = plt.subplots()
    ax.plot(df['ASSET'].values, df['DETECTED'].values, color="#E63946", marker='D') 

    # Set Title
    ax.set_title('Heicoders Academy Annual Sales', fontweight="bold")

    # Set xticklabels
    ax.set_xticklabels(df['ASSET'].values, rotation=90)
    plt.xticks(df['ASSET'].values)

    # Set ylabel
    ax.set_ylabel('DETECTED')

    # Save the plot as a PNG
    plt.savefig(filename, dpi=600)
    
    plt.show()

def generate_matplotlib_piechart(df, filename):
    labels = "Severity"
    
    # Pie chart, where the slices will be ordered and plotted counter-clockwise:
    labels = ["Severity"]
    sales_value = df["Severity"].tail(1)
    
    # Colors
    colors = ['#E63946','#F1FAEE','#A8DADC','#457B9D','#1D3557', '#9BF6FF']
    
    # Create subplot
    fig, ax = plt.subplots()
    
    # Generate pie chart
    ax.pie(sales_value, labels=labels, autopct='%1.1f%%', startangle=90, colors = colors)
    ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    
    # Set Title
    ax.set_title('Heicoders Academy 2016 Sales Breakdown', fontweight="bold")
    
    # Save the plot as a PNG
    plt.savefig(filename, dpi=300, bbox_inches='tight', pad_inches=0)
    
    plt.show()

def generateImages():

    df = pd.read_csv('reports\\EndpointIncidentesVulnerabilities.csv')
    #df.columns = ['ASSET','CVE','SEVERITY','TYPE','PUBLISHER','PRODUCT','EVENTDATE']    

    #print(df)

    conn = sqlite3.connect('IncidentsVulnerabilities')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS endpointincidentsvuls (asset,cve,severity,type,publisher,product,eventdate)')
    conn.commit()

    df.to_sql('endpointincidentsvuls', conn, if_exists='replace', index = False)

    #c.execute('''SELECT *,COUNT(*) as num FROM endpointincidentsvuls GROUP BY asset HAVING COUNT(*)>1 ORDER BY name,MAX(eventdate)''')
    #c.execute('''SELECT * FROM endpointincidentsvuls ORDER BY asset''')
    #c.execute('''SELECT severity,COUNT(*) FROM endpointincidentsvuls GROUP BY severity''')
    #c.execute('''SELECT COUNT(*),asset,type FROM endpointincidentsvuls GROUP BY asset,type''')


    #for row in c.fetchall():
        #print(row)

    #c.execute('''SELECT asset,severity,type,datetime(eventdate/1000, 'unixepoch', 'localtime'),eventdate,COUNT(*) as num FROM endpointincidentsvuls GROUP BY asset,severity,type ORDER BY asset,num DESC''')
    
    #Top 10 Assets
    c.execute('''SELECT asset,ifnull(detected, 0) AS detected,ifnull(mitigated, 0) AS mitigated,(ifnull(detected, 0)-ifnull(mitigated, 0)) as activevul FROM 
                (SELECT MAX(CASE WHEN type = 'DetectedVulnerability' THEN num END) AS 'detected',
                        MAX(CASE WHEN type = 'MitigatedVulnerability' THEN num END) AS 'mitigated',asset                
                FROM (SELECT COUNT(*) as num,asset,type,severity,cve FROM endpointincidentsvuls GROUP BY asset,type) 
                    GROUP BY asset) ORDER BY activevul DESC LIMIT 10''')

    #for row in c.fetchall():
        #print(row)
    
    #df = pd.DataFrame(c, columns = ['DATE', 'DETECTED', 'MITIGATED', 'ACTIVEVUL'])
    #df = df.astype({'DETECTED':'int'})
    #df = df.astype({'MITIGATED':'int'})
    #pd.options.display.float_format = '{:,.0f}'.format

    #generate_matplotlib_stackbars(df,'resources\\bartest.png')
    #generate_cyber(df)

    
    #print(df)
    
    #df = df.style.set_table_styles([dict(selector='th', props=[('text-align', 'center'),('background-color', '#40466e'),('color', 'white')])])
    
    #df.set_properties(**{'text-align': 'center'}).hide(axis='index')
    #pd.set_option('colheader_justify', 'center')

    
    ## install wkhtmltoimage
    #config = imgkit.config(wkhtmltoimage='C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltoimage.exe')
    #html = df.to_html()    
    #imgkit.from_string(html, "ff1.png", config=config)
    
    #imgkit.from_string(html, "ff1.png")

    #dfi.export(df, 'resources\\ff1.png')

    c.execute('''SELECT monthyear,severity,MAX(CASE WHEN type = 'DetectedVulnerability' THEN num END) AS 'detected',
                        MAX(CASE WHEN type = 'MitigatedVulnerability' THEN num END) AS 'mitigated'                
                FROM (SELECT COUNT(*) as num,type,severity,strftime("%m-%Y", datetime(eventdate/1000, 'unixepoch', 'localtime')) as monthyear FROM endpointincidentsvuls GROUP BY strftime("%m-%Y", datetime(eventdate/1000, 'unixepoch', 'localtime')),type,severity) GROUP BY monthyear,severity''')
    conn.commit()
    #strftime("%m-%Y", datetime(eventdate/1000, 'unixepoch', 'localtime')) as 'month-year'



    #time.sleep(2)
    #df2 = pd.DataFrame(c)
    #pd.options.display.float_format = '{:,.0f}'.format
    #print(df2)
    #convert points, rebounds, and blocks columns to numeric
    #df2['DETECTED']=df['DETECTED'].astype(float)
    #df2['MITIGATED']=df['MITIGATED'].astype(float)
    #df['blocks']=df['blocks'].astype(float)
    #generate_cyber(df2)
    #df2.plot(marker='o')
    #plt.show()

    #Pie Severity
    c.execute('''SELECT severity,MAX(CASE WHEN type = 'DetectedVulnerability' THEN num END) AS 'detected'
            FROM 
            (SELECT COUNT(*) as num,type,severity FROM endpointincidentsvuls 
                WHERE type = 'DetectedVulnerability'
                    GROUP BY severity)GROUP BY severity ORDER BY 
                                                                CASE severity
                                                                    WHEN 'Critical' THEN 0
                                                                    WHEN 'High' THEN 1
                                                                    WHEN 'Medium' THEN 2
                                                                    WHEN 'Low' THEN 3
                                                                END''')
    conn.commit()

    #for row in c.fetchall():
        #print(row)
    
    df = pd.DataFrame(c,columns=['severity','detected'])
    
    print(df)
    dfi.export(df, 'resources\\ffp.png')
    plt.pie(df['detected'],labels=df['severity'])
    plt.show()


def generate_cyber(df):
    plt.style.use("dark_background")
    for param in ['text.color', 'axes.labelcolor', 'xtick.color', 'ytick.color']:
        plt.rcParams[param] = '0.9'  # very light grey
    for param in ['figure.facecolor', 'axes.facecolor', 'savefig.facecolor']:
        plt.rcParams[param] = '#212946'  # bluish dark grey
    colors = [
        '#08F7FE',  # teal/cyan
        '#FE53BB',  # pink
        '#F5D300',  # yellow
        '#00ff41',  # matrix green
    ]
    
    fig, ax = plt.subplots()
    df.plot(marker='o', color=colors, ax=ax)
    #ax.plot(df['ASSET'].values, df['DETECTED'].values, color="#E63946", marker='D') 
    #ax.set_xticklabels(df['ASSET'].values, rotation=90)
    # Redraw the data with low alpha and slighty increased linewidth:
    n_shades = 10
    diff_linewidth = 1.05
    alpha_value = 0.3 / n_shades
    for n in range(1, n_shades+1):
        df.plot(marker='o',
                linewidth=2+(diff_linewidth*n),
                alpha=alpha_value,
                legend=False,
                ax=ax,
                color=colors)
    # Color the areas below the lines:
    for column, color in zip(df, colors):
        ax.fill_between(x=df.index,
                        y1=df[column].values,
                        y2=[0] * len(df),
                        color=color,
                        alpha=0.1)
    ax.grid(color='#2A3459')
    ax.set_xlim([ax.get_xlim()[0] - 0.2, ax.get_xlim()[1] + 0.2])  # to not have the markers cut off
    ax.set_ylim(0)
    plt.show()

generateImages()
