# Load pandas
import pandas as pd

# Read CSV file into DataFrame df
dftask = pd.read_csv('VickyReportApiTasksEvents_v1.0.csv')
# Read Vunlerabilits
dfvuln = pd.read_csv('VickyReportApiTasksEvents_v1.0.csv')
# Read PatchInventary
dfproduct = pd.read_csv('VickyReportApiEndpointPublisherProductVersions.csv')

# Show dataframe
print(dftask)
print(dfvuln)
print(dfproduct)

# Create a Pandas Excel writer using XlsxWriter as the engine.
excel_file = 'TopiaReport.xlsx'
sheet_name = 'Task Status'

# Create a Pandas Excel writer using XlsxWriter as the engine.
writer = pd.ExcelWriter(excel_file, engine='xlsxwriter')

# Convert the dataframe to an XlsxWriter Excel object.
#df.to_excel(writer, sheet_name=sheet_name)
dftask.to_excel(writer, sheet_name=sheet_name, startrow=1, header=False, index=False)
dfvuln.to_excel(writer, sheet_name='Vunerability', startrow=1, header=False, index=False)
dfproduct.to_excel(writer, sheet_name='Softwares', startrow=1, header=False, index=False)

# Get the xlsxwriter workbook and worksheet objects.
workbook  = writer.book
worksheet = writer.sheets[sheet_name]

# Get the dimensions of the dataframe.
(max_row, max_col) = dftask.shape

# Create a list of column headers, to use in add_table().
column_settings = [{'header': column} for column in dftask.columns]

# Add the Excel table structure. Pandas will add the data.
worksheet.add_table(0, 0, max_row, max_col - 1, {'columns': column_settings})

# Make the columns wider for clarity.
worksheet.set_column(0, max_col - 1, 12)

########

# Get the xlsxwriter workbook and worksheet objects.
worksheet2 = writer.sheets['Vunerability']

# Get the dimensions of the dataframe.
(max_row, max_col) = dfvuln.shape

# Create a list of column headers, to use in add_table().
column_settings = [{'header': column} for column in dfvuln.columns]

# Add the Excel table structure. Pandas will add the data.
worksheet2.add_table(0, 0, max_row, max_col - 1, {'columns': column_settings})

# Make the columns wider for clarity.
worksheet2.set_column(0, max_col - 1, 12)

########

# Get the xlsxwriter workbook and worksheet objects.
worksheet3 = writer.sheets['Softwares']

# Get the dimensions of the dataframe.
(max_row, max_col) = dfproduct.shape

# Create a list of column headers, to use in add_table().
column_settings = [{'header': column} for column in dfproduct.columns]

# Add the Excel table structure. Pandas will add the data.
worksheet3.add_table(0, 0, max_row, max_col - 1, {'columns': column_settings})

# Make the columns wider for clarity.
worksheet3.set_column(0, max_col - 1, 12)

# Close the Pandas Excel writer and output the Excel file.
writer.save()




