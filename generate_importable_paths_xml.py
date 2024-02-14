# generate_importable_paths_xml.py
# Version: 1.0
# Last updated: 2024-02-14
# Patrick Van Zandt <patrick@airlockdigital.com>, Principal Customer Success Manager

'''
This is a simple utility for creating XML files which are importable in the Airlock
management console GUI under "Policies > [select a policy] > Paths > [right click] >
Import XML" based on a list of paths that you either type into the command prompt
window or (much more commonly) paste in from a text file or spreadsheet.
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

# Main method that gets invoked at runtime
def main():

    # Get the list of paths
    paths_list = prompt_for_paths()
    
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