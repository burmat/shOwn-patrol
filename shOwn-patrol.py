import shodan
import argparse
import os
import xlsxwriter
import inquirer

IP_COL = 0
CVE_NUM_COL = 1
VERIFIED_COL = 2
CVSS_SCORE_COL = 3
CVE_REF1_COL = 4
CVE_REF2_COL = 5
SUMMARY_COL = 6

def main(api_key, ips_list):

	# init the api
	try:
		shodan_api = shodan.Shodan(api_key)
		shodan_api.info()
	except shodan.APIError as e:
		print(f'[!] ERROR: {e} - Exiting.')
		exit(1)

	# create the workbook and header row
	print('[>] Initializing the workbook')
	row = 0
	workbook = xlsxwriter.Workbook('CVEs.xlsx')
	wrap_format = workbook.add_format({'text_wrap': True})
	sheet = workbook.add_worksheet('Shodan CVEs')
	sheet.write(row, IP_COL, 'IP Address', wrap_format)
	sheet.write(row, CVE_NUM_COL, 'CVE Number', wrap_format)
	sheet.write(row, VERIFIED_COL, 'Verified', wrap_format)
	sheet.write(0, CVSS_SCORE_COL, 'CVSS Score', wrap_format)
	sheet.write(0, CVE_REF1_COL, 'CVE.org URL', wrap_format)
	sheet.write(0, CVE_REF2_COL, 'CVEdetails.org URL', wrap_format)
	sheet.write(0, SUMMARY_COL, 'CVE Summary', wrap_format)

	# for each ip in the list, look them up in shodan
	with open(ips_list, 'r') as file:
		for ip_addr in file:
			host = None;
			ip_addr = ip_addr.strip()
			print(f'[>] {ip_addr}: Querying')
			if ip_addr != '':
				try:
					host = shodan_api.host(ip_addr)
				except shodan.APIError as e:
					if 'No information available for that IP.' in e.value:
						print(f'[-] {ip_addr}: No record in Shodan')
						continue
					else:
						print(f'[!] ERROR: {e} - Exiting.')
						exit(1)
						
			# determine if there are vulnerabilities. add to excel workbook if so.
			if host:
				for data_obj in host['data']:
					if 'vulns' in data_obj:
						print(f'[+] {ip_addr}: CVE entries discovered.')
						for cve in data_obj['vulns']:
							row += 1
							cve_data = data_obj['vulns'][cve]
							sheet.write(row, IP_COL, ip_addr, wrap_format)
							sheet.write(row, CVE_NUM_COL, cve, wrap_format)
							sheet.write(row, VERIFIED_COL, cve_data["verified"], wrap_format)
							sheet.write(row, CVSS_SCORE_COL, cve_data["cvss"], wrap_format)
							sheet.write(row, CVE_REF1_COL, f'https://www.cve.org/CVERecord?id={cve}', wrap_format)
							sheet.write(row, CVE_REF2_COL, f'https://www.cvedetails.com/cve/{cve}/', wrap_format)
							sheet.write(row, SUMMARY_COL, cve_data["summary"], wrap_format)
			else:
				print(f'[!] There was an error with the data returned - Exiting.')
				exit(1)

	sheet.autofit()
	workbook.close()
	print(f'[*] FINISHED!')
	exit(0)

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='This app will grab CVEs based on an IP address', allow_abbrev=False)
	parser.add_argument('--file', required=True, help='The name of the hosts you want to lookup (IP ADDRESS ONLY!)')
	args = parser.parse_args()
	if os.path.exists(args.file):
		question = [inquirer.Password('api_key', message='Shodan API Key')]
		answer = inquirer.prompt(question)
		api_key = answer['api_key']
		main(api_key, args.file)
	else:
		print('[!] Filepath does not exist - Double check it. Exiting.')
		exit(1)
