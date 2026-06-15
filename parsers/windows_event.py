import xml.etree.ElementTree as ET

def parse_windows_log(filepath: str) -> list:
    events = []

    # Microsoft namespace required for all element lookups in Windows Event XML
    ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}

    # Parse the XML file into an ElementTree and get the root <Events> element
    tree = ET.parse(filepath)    
    root = tree.getroot()

    # Each <Event> element is one Windows log entry
    for event in root.findall('e:Event', ns):

         # System section contains metadata about the event
        system = event.find('e:System', ns)
        event_id = system.find('e:EventID', ns).text # type: ignore 
        time = system.find('e:TimeCreated', ns).get('SystemTime') # type: ignore 
        computer = system.find('e:Computer', ns).text # type: ignore 

        # EventData contains variable fields depending on the EventID
        # Extract all Data elements generically into a dict
        data_dict = {}
        for data in event.findall('e:EventData/e:Data', ns):
            data_dict[data.get('Name')] = data.text

        events.append({
            "event_id": event_id,
            "time": time,
            "computer": computer,
            "data": data_dict
        })

    return events