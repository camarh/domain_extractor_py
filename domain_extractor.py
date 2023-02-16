#!/usr/bin/env python3

# Required packages
import re
import sys
import argparse
from colorama import Fore, Back, Style


# ------------------------------------------------------------------------------------------------------

class ExtractCertificates:

    def __init__(self, data):
        """
        Initialize class instance and define attribute on the object.
        :param data: Data lines ingested from stdin or from text file. It's basically lines in Pcap file.
        """
        self.__data = data

    def extract_data(self) -> dict:
        """
        Store and arrange data lines ingested according to their row number in a dictionary.
        :return: Dictionary that contains key-value pair structured data.
        """
        data = dict()
        for i, line in enumerate(self.__data):
            if line.strip:
                data[str(i + 1)] = line.strip()
        return data

    @staticmethod
    def process_intermediate_step(key, last_key, collection, pattern, action='STORE') -> dict or str:
        """
        Generic loop function that browse through a given dictionary (line by line) to process 2 types of intermediate steps.
            - Type 1 [STORE action]: Store data lines in a dictionary until specific pattern is meet.
            - Type 2 [JUMP action]: Increments key (row number) until specific pattern is meet, so we could jump with that key to a specific line.
        :param key: Key of the matching search.
        :param last_key: Last key of the given dictionary.
        :param collection: Dictionary that contains key-value pair structured data.
        :param pattern: Pattern to match specific line and serves as control statement to terminate the loop.
        :param action: Trigger called action - STORE (default) or JUMP
        :return: Dictionary that contains intermediate step data or the interesting key, according to the called action.
        """
        data = dict()
        # As long as the given line don't start with the pattern and that the dictionary is not exhausted in terms of line
        while key < last_key and not re.match(pattern, collection.get(str(key))):
            # Store the given line or ...
            if 'STORE' in action:
                data[str(key)] = collection.get(str(key))
                key += 1
            # Just increment the key
            elif 'JUMP' in action:
                key += 1
        return data if data else str(key)

    def sort(self, **kwargs) -> dict:
        """
        Pack the received data in a dict after having processed intermediate steps:
            - Preliminary sorting: Organize data in bloc and structure them frame by frame in a temporary dict
            - Finer sorting: Retrieve the interesting data from the previous dict and store it in a second dict before fetching domains in a final dict
        :param kwargs: Key-value pair structured data to pack in dict.
        :return: Dict that contains domains
        """
        patterns = (r'RelativeDistinguishedName item \(id-at-commonName=', 'uTF8String: |printableString: ')
        temp_dict_2 = dict()
        data = dict()
        certificates_block_start = ''
        domain = ''
        for k, v in kwargs.items():
            # Preliminary step 1
            # When the line starts with 'Internet Protocol Version 4'...
            if v.startswith('Internet Protocol Version 4'):
                new_record = True
                ip_line = k
                frame_ip = v.split()[5].strip(",")
                index = f'{frame_ip} {k}'
                # ... begins storing all subsequent rows in a dict until encountering a row beginning with 'Frame '
                temp_dict_1 = self.process_intermediate_step(int(k), len(kwargs), kwargs, 'Frame ')

                for dict_1_key, dict_1_value in temp_dict_1.items():
                    # Preliminary step 2
                    # When the line 'Handshake Protocol: Certificate' is found...
                    if re.search(r'^Handshake Protocol: Certificate$', dict_1_value):
                        certificates_block_start = dict_1_key
                        # ... begins storing all subsequent rows in a dict until encountering a row beginning with 'Handshake Protocol: ' 
                        #     and does not end with 'Certificate'
                        temp_dict_2 = self.process_intermediate_step(int(dict_1_key), len(temp_dict_1) + int(ip_line), temp_dict_1, r'Handshake Protocol: (?!Certificate$).+')

                for dict_2_key, dict_2_value in temp_dict_2.items():
                    if dict_2_value.startswith('subject: rdnSequence'):
                        # Final steps
                        # When the line starts with 'subject: rdnSequence'...
                        for p in patterns:
                            # ... increment the line key to that of the domain line of the certificate
                            dict_2_key = self.process_intermediate_step(int(dict_2_key), len(temp_dict_2) + int(certificates_block_start) - 1, temp_dict_2, p, r'JUMP')

                        # With the returned key, fetch the line only if it starts with 'uTF8String: |printableString: ' and ...
                        # Safeguard condition in cases where a line that starts with 'subject: rdnSequence' exits and the iteration goes to the end of the dict without finding a line that starts with 'RelativeDistinguishedName item \(id-at-commonName='
                        if re.match(patterns[1], temp_dict_2.get(dict_2_key)):
                            # ... slice the line to extract just the value (certificate domain) and store it
                            domain = re.split(patterns[1], temp_dict_2.get(dict_2_key)).__getitem__(1)

                        # Main dict which will contain the final result
                        for key in list(data):
                            old_key = key
                            # If the key starts with the frame IP, we're just going to update our line
                            if re.match(rf'{frame_ip}.+', key):
                                new_domain = data[key]
                                # Concatenate the frame IP and its row number in case the frame does not contain multiple certificates
                                if not re.search(rf' {ip_line}', key):
                                    key = f'{key} {ip_line}'
                                    data[key] = new_domain
                                    data.pop(old_key)
                                # Avoid duplicates before storing the domain
                                if domain not in new_domain:
                                    data[key].append(domain)
                                # As it's an update, set the reference variable to False
                                new_record = False
                        # Simple handling of new records
                        if new_record:
                            data[index] = [domain]
        return data


def main():

    domain = []

    parser = argparse.ArgumentParser(prog='EXTRACT-CERTIFICATE-DOMAIN-APP', description='Generic pcap file parser application to extract certificate domain', exit_on_error=False)
    parser.add_argument('-i', '--input', type=argparse.FileType('r'), default=sys.stdin, help='Stream to read could be from the stdin or from a txt file (default is stdin)')
    parser.add_argument('-f', '--format', type=str, default='table', choices=['table', 'list'], help='Format output with extra info in a table or just print out all unique domains (fqdn) in list (default is table)')

    try:
        args = parser.parse_args()
        inputs = args.input
        formats = args.format
        ec_instance = ExtractCertificates(inputs)           # Initiate an instance of the class to retrieve parser data
        data_in_dict = ec_instance.extract_data()
        data_sort = ec_instance.sort(**data_in_dict)

        # Format and structure result in a table
        if 'table' in formats:
            for key, val in data_sort.items():
                key = key.split()
                print()
                print(Fore.BLACK + Style.BRIGHT + Back.WHITE + '{:24}{:100}'.format('IP Address', key[0]) + Style.RESET_ALL)
                print(Fore.CYAN + Style.BRIGHT + Back.BLACK + '{:24}\033[35m{:<100}\033[0m'.format('Number of frames', len(key)-1) + Style.RESET_ALL)
                print(Fore.CYAN + Style.BRIGHT + Back.BLACK + '{:24}\033[35m{:100}\033[0m'.format('Row number', ', '.join(key[1:])) + Style.RESET_ALL)
                print(Fore.CYAN + Style.BRIGHT + Back.BLACK + '{:24}\033[35m{:100}\033[0m'.format('Domain', '\n\t\t\t'.join(val)) + Style.RESET_ALL)
                print()

        # Format result in a bare list of domains (fqdn) that is cleared of duplicates
        else:
            for d_list in data_sort.values():
                for d in d_list:
                    if re.match(r'^[^ ]+\.[^ ]*$', d) and d not in domain:
                        domain.append(d)

            # Sort domains alphabetically
            domain.sort()

            print()
            print(Fore.MAGENTA + Style.BRIGHT + Back.BLACK)
            print(*domain, sep='\n')
            print(Style.RESET_ALL)
            print()

    except Exception as e:
        e = type(e).__name__
        print(f'\nThe process exits with the following error : {e}\n'
              f'\nPlease provide either a valid argument or a valid text document and follow below usage\n')
        parser.print_help()
        exit(1)


if __name__ == '__main__':
    main()
