# generate_importable_paths_xml.py
# Version: 1.2
# Last updated: 2024-02-15
# Patrick Van Zandt <patrick@airlockdigital.com>, Principal Customer Success Manager

'''
This is a simple utility for creating XML files which are importable in the Airlock
management console GUI under "Policies > [select a policy] > Paths > [right click] >
Import XML" based on a list of paths that you either type/paste into the command prompt
window or read from a text or OOXML Excel file on disk.

Given the challenges with directly supporting CDATA in xml.etree.ElementTree and the 
difficulty with string replacement (believe me, I tried!) I took a very manual
approach in building the XML content so thateach path is wrapped in a CDATA section
as required by Airlock. There are surely more elegant ways to achieve this same outcome,
but this method gets the job done as long as you provide valid input.

Unlike many examples in this same Github project, this script does not interact with the
Airlock server directly. It is just a utility for you to run to create an XML file which
you can then use for import in the Airlock GUI. Therefore no server name or API key is 
required.
'''

# Method to convert a list of strings into XML format matching what Airlock uses for export and import
def paths_to_xml(paths_list):
    print('\nConstructing XML based on the', len(paths_list), 'provided paths\n')
    # XML header
    xml_output = '<?xml version="1.0" encoding="utf-8"?>\n'
    xml_output += '<PathExport>\n'
    xml_output += '\t<Paths>\n'
    
    # Iterate over each path, adding them with CDATA sections
    for path in paths_list:
        xml_output += '\t\t<path>\n'
        xml_output += '\t\t\t<name><![CDATA[' + path + ']]></name>\n'
        xml_output += '\t\t</path>\n'
    
    xml_output += '\t</Paths>\n'
    xml_output += '</PathExport>'
    
    print(xml_output)
    return xml_output

# Method to write XML content to disk
def xml_to_disk(xml_output, file_name):
    print('\nWriting to', file_name)
    with open(file_name, 'w', encoding='utf-8') as file:
        file.write(xml_output)

# Method to build a list of paths based on a user typing or pasting them in
def prompt_for_paths():
    paths_list = []
    print('\nEnter paths below, one per line, with no quotes or other wrapping characters.',
          'You can paste in multiple paths from a text document or spreadsheet. When done,',
          'enter no value and press return to save the list.\n')
    while True:
        path = input('Enter a path: ')
        if len(path) > 0:
            paths_list.append(path)
        else:
            break
            
    print('\nDone collecting paths. This is what was entered:\n', paths_list)
    return paths_list

# Method to read a list of paths from a text file on disk
def read_txt_from_disk(file_name):
    paths_list = []
    print('\nReading paths from', file_name)
    with open(file_name, 'r') as file:
        for line in file:
            path = line.strip().strip('"').strip("'")
            if len(path) > 0: #skips blank lines
                paths_list.append(path)
    print('\nDone collecting paths. This is what was imported:\n', paths_list)
    return paths_list

# Method to read a list of paths from an Excel file on disk
def read_xlsx_from_disk(file_name):
    import pandas
    df = pandas.read_excel(file_name, sheet_name=0)
    records = df.to_dict('records')
    paths_list = []
    for record in records:
        path = record['File - File Path'] + record['File - File Name']
        paths_list.append(path)
    return paths_list

# Method to determine which mode to run in based on user input
def get_mode():
    print('This script works in three modes\nA. Read paths from a TXT file on disk\nB. Type or paste paths into command shell\nC. Read paths from an XLSX',
    'file on disk')
    user_input = input('Enter the letter representing the mode you want to use: ')
    if user_input.lower() == 'a':
        return 'txt'
    elif user_input.lower() == 'b':
        return 'paste'
    elif user_input.lower() == 'c':
        return 'excel'
    
# Main method that gets invoked at runtime
def main():

    mode = get_mode()

    if mode == 'paste':
        paths_list = prompt_for_paths()
    
    elif mode == 'txt':
        file_name = input('\nEnter file name to import from, or press return to use the default (paths.txt): ')
        if file_name == '':
            file_name = 'paths.txt'
        paths_list = read_txt_from_disk(file_name)
    
    elif mode == 'excel':
        print('\nNote: The mode you selected reads an Excel workbook and combines the data in columns labeled',
              '"File - File Path" and "File - File Name" in the first sheet to create path values.')
        file_name = input('\nEnter file to import from, or press return to use the default (paths.xlsx): ')
        if file_name == '':
            file_name = 'paths.xlsx'
        paths_list = read_xlsx_from_disk(file_name)       
    
    # Convert list of paths to XML
    paths_xml = paths_to_xml(paths_list)
    
    # Prompt for output file name
    file_name = input('\nEnter file name to export the above to, or press return to use the default (paths.xml): ')
    if file_name == '':
        file_name = 'paths.xml'
        
    # Write data to disk
    xml_to_disk(paths_xml, file_name)
    
    print('\nDone.')

# Invoke main() method when PY file is run
if __name__ == '__main__':
    main()
