"""
Little snitch rules to block adware and malware websites. Host lists from Steven Black.
"""

# Standard library imports
import urllib.request
import io
import re
import json

#----------------------------------------------------------------------

class GenerateLittleSnitchRules():

	HOST_FILE_URL 	= "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
	OUT_FILENAME 	= "adware_malware_list.lsrules"

	def __init__(self):
		self.data 		= self.fetch_data()
		self.rules		= self.extract_hosts(self.data) 		
		self.generate_ruleset(self.rules)

	def fetch_data(self):
		#----------------------------------------------------------------------
		# Retrieve host lists from Steven Black
		# @return: list containing the lines
		#----------------------------------------------------------------------

		u = urllib.request.urlopen(self.HOST_FILE_URL, data = None)
		f = io.TextIOWrapper(u, encoding="utf-8")
		text = f.readlines()
		return text

	def extract_hosts(self, data):
		#----------------------------------------------------------------------
		# Extract urls found in sitemap and follow to submaps e.g. SEO Yoast
		# @param: data - blacklisted host list
		# @return: array of ls formatted domain rules
		#----------------------------------------------------------------------
		
		# Only keep hostnames that follow 0.0.0.0, while removing trailing comments.
		pattern = re.compile("^0.0.0.0 ([^#]*)(#.*)?")

		rules = []

		for line in self.data:
			match = pattern.search(line)
			if match is not None:
				# First group is the hostname, second group is the comment (optional).
				hostname = match.group(1).strip()
				if hostname != "0.0.0.0":
					rules.append({"action":"deny", "process":"any", "remote-domains":hostname})
				
		return rules

	def generate_ruleset(self, rules):
		#----------------------------------------------------------------------
		# Generate JSON file for little snitch
		# @param: rules - array of ls formatted domain rules
		#----------------------------------------------------------------------

		data = {}
		data["name"] = "Block adware and malware"
		data["description"] = "Little snitch rules to block adware and malware websites. Host lists from Steven Black."
		data["rules"] = self.rules

		# Write JSON to file and download
		with open(self.OUT_FILENAME, 'w') as json_file:
			json.dump(data, json_file, indent=2)

# End GenerateLittleSnitchRules Class
#----------------------------------------------------------------------		

if __name__ == '__main__':
	GenerateLittleSnitchRules()