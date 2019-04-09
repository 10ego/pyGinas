# version 0.71
import requests
import multiprocessing
from datetime import datetime
import json
import os
from uuid import uuid4

class pyGinasLogger():
	def __init__(self, logfile):
		try:
			if os.path.isdir('log'):
				pass
			else:
				os.makedirs('log')
			self.logfile = "log/{}.log".format(logfile)
			# self.logfile_uploads = 'log/{}_uploads.log'.format(logfile)
		except IOError as exception:
			raise IOError("{}: {}".format(path, exception.strerror))
		return None
	
	def log(self, type, message):
		timestamp = datetime.strftime(datetime.now(), "%Y-%m-%d %H:%M:%S (%z)")
		with open(self.logfile, 'a+') as log:
			log.write("[{}] [{}] {}".format(timestamp, type, message))
			log.write("\n\n")
			
class API():
	def __init__(self, schema = None):
		self.BASE_URL = "https://tripod.nih.gov/ginas/app/api/v1"
		self.MY_URL = "https://srs.hres.ca/ginas/app/api/v1"
		self.USERNAME = None
		self.PASSWORD = None
		self.ApprovalName = None
		self.ApprovalPass = None
		self.logger = pyGinasLogger('pyGinas')
		self.SCHEMA = schema
		
	def _setMySRS(self, uri):
		self.MY_URL = uri
	
	def _setSchema(self, schema):
		self.SCHEMA = schema
		self.logger.log("Msg", "Schema set to '{}'".format(self.SCHEMA))
	
	def _buildCode(self, code_id, code_system, url = None, ref=[], self_ref="", type = "PRIMARY",  deprecated = False, access=[]):
		
		code = {}
		code['_self'] = self_ref  # Self link to reference the code
		code['code'] = str(code_id)
		code['codeSystem'] = code_system
		code['type'] = type
		code['deprecated'] = deprecated
		code['references'] = ref
		code['access'] = access
		code['uuid'] = str(uuid4()) # Must generate a new UUID for each new entry
		code['url'] = url
		
		uuid_valid = False
		while uuid_valid is False:
			v = requests.get(self.MY_URL + "/codes({})".format(code['uuid']))
			if 200 <= v.status_code < 300:
				code_data['uuid'] = str(uuid4())
				self.logger.log("Warning", "Code collision prevented for '{}'.".format(code['uuid']))
			else:
				code['_self'] = self.MY_URL+"/codes({})?view=full".format(code['uuid'])
				uuid_valid = True
				self.logger.log("Msg", "Buliding custom code. Code '{}' assigned.".format(code['uuid']))
		return code

	def _validateSchema(self):
		if self.SCHEMA is None:
			raise ValueError("Schema is set to None.")
			self.logger.log("Error", "No schemas set.")
		elif self.SCHEMA in ['references', 'edits', 'substances', 'structures', 'scheduledjobs', 'backups', 'xrefs', 'codes', 'values', 'vocabularies', 'keywords', 'names', 'payload', 'jobs']:
			pass
		else:
			raise ValueError('{} is not a supported schema'.format(self.SCHEMA))
			self.logger.log("Error", "{} is not a supported schema".format(self.SCHEMA))
	def _validateAuth(self):
		if self.USERNAME is None or self.PASSWORD is None:
			self.authenticate()
	def _validateApprovalAuth(self):
		if self.ApprovalName is None or self.ApprovalPass is None:
			self._authenticateApproval()
			
	def _validateThis(self, data):
		data = data.copy()
		del data['approvalID']
		yield data
		
	def _authenticateApproval(self, username=None, password=None): # Only for calling approval() function
		if username is None:
			self.ApprovalName = input("Approval Name: ")
		else:
			self.ApprovalName = username
		if password is None:
			self.ApprovalPass = input("Approval Password: ")
		else:
			self.ApprovalPass = password
		self.ApprovalHEADER = {"auth-username" : self.ApprovalName, "auth-password" : self.ApprovalPass, "Content-Type":"application/json"}
		self.logger.log("Msg", "Approval using account '{}' authenticated by '{}'".format(self.ApprovalName, self.USERNAME))
		
	def authenticate(self, username=None, password=None):
		if username is None:
			self.USERNAME = input("Username: ")
		else:
			self.USERNAME = username
		if password is None:
			self.PASSWORD = input("Password: ")
		else:
			self.PASSWORD = password
		self.HEADER = {"auth-username" : self.USERNAME, "auth-password" : self.PASSWORD, "Content-Type":"application/json"}
		self.logger.log("Msg", "User '{}' authenticated".format(self.USERNAME))
		
	def search(self, term):
		self._validateSchema()
		query_url = self.BASE_URL + "/{}/search?q={}".format(self.SCHEMA, str(term))
		try:
			r = requests.get(query_url)
			if 200 <= r.status_code < 300:
				result = r.json()['content']
				
				if result == []:
					print("No results found for '{}'.".format(term))
					self.logger.log("Warning", "No results found for '{}'.".format(term))
					return None
				else:
					name = result[0]['_name']
					if name.lower() != term.lower():
							print("Exact match not found for '{}'. Returning next best match ({}).".format(term, name))
							self.logger.log("Warning", "Exact match not found for '{}'. Returning next best match ({}).".format(term, name))
					else:
						print("Exact match found for '{}'.".format(term))
						self.logger.log("Msg", "Exact match found for '{}'.".format(term))
					return result[0]
			else:
				self.logger.log("Error", "Error code {}! Search call failed for '{}'.".format(r.status_code, term))
				print("Error", "Error code {}! Search call failed for '{}'.".format(r.status_code, term))
				return None
		except Exception as e:
			self.logger.log("Error", "{} Error. Search call on '{}' failed. {}".format(type(e), term, e.args))
			print("{} Error. Search call on '{}' failed. {}".format(type(e), term, e.args))
			return None
		
	
	def getFull(self, uuid):
		self._validateSchema()
		url = self.BASE_URL + "/{}({})?view=full".format(self.SCHEMA, uuid)
		r = requests.get(url)
		try:
			if 200 <= r.status_code < 300:
				self.logger.log("Msg", "Retrieved full data from uuid: '{}'".format(uuid))
				return r.json()
			else:
				self.logger.log("Error", "Error code {}! Search call failed for '{}' failed.".format(r.status_code, term))
				print("Error code{}! Search call to '{}' failed.".format(r.status_code, url))
				return None
		except Exception as e:
			self.logger.log("Error", "{} Error. Search call failed for '{}' failed. See args - ".format(type(e), term, e.args))
			print("{} Error. Search call failed for '{}' failed. See args - ".format(type(e), term, e.args))
			return None
		
	
	def validate(self, data):
		self._validateSchema()
		self._validateAuth()
		url = self.MY_URL + "/{}/@validate".format(self.SCHEMA)
		if 'approvalID' in data:
			data = next(self._validateThis(data))
			
		try:
			r = requests.post(url = url, headers=self.HEADER, data = json.dumps(data))
			if 200 <= r.status_code < 300:
				return r.json()
			else:
				try:
					self.logger.log("Error", "Error code {}! Validation call for '{}' failed. See details - {}".format(r.status_code, data['_name'], r.json()))
					print("Error code {}! Validation call for {} failed.".format(r.status_code, data['_name']))
				except Exception as e:
					self.logger.log("Error", "Error code {}! Validation call for '{} 'failed. {} ERROR on args {}. See details - {}".format(r.status_code, data['_name'],type(e), e.args, r.text))
				return None
		except Exception as e:
			self.logger.log("Error", "POST request for {} at '{}' failed. {} ERROR on args {}.".format(data['_name'], url, type(e), e.args))
			return None
		

	def upload(self, data):
		self._validateSchema()
		self._validateAuth()
		url = self.MY_URL + "/{}".format(self.SCHEMA)
		try:
			r = requests.post(url = url, headers = self.HEADER, data = json.dumps(data))
			if 200 <= r.status_code < 300:
				self.logger.log("Msg", "Upload success ({})!".format(data['_name']))
				print("Upload success ({})!".format(data['_name']))
			else:
				self.logger.log("Error", "Error code {}! Upload call for '{}' failed. See details - {}".format(r.status_code, data['_name'], r.text))
				print("Error code {}! Upload call for '{}' failed.".format(r.status_code, data['_name']))
		except Exception as e:
			self.logger.log("Error", "POST request for {} at '{}' failed. {} ERROR on args {}.".format(data['_name'], url, type(e), e.args))		

	# def update(self, data): # custom_code should be dictionary output of self._buildCode()
		# self._validateSchema()
		# if self.USERNAME is None or self.PASSWORD is None:
			# self.authenticate()
		
		# url = self.MY_URL + "/{}".format(self.SCHEMA)
		# r = requests.put(url = url, headers = self.HEADER, data = json.dumps(data))
		# if 200 <= r.status_code < 300:
			# self.logger.log("Msg", "Update success ({})!".format(data['_name']))
			# print("Update success ({})!".format(data['_name']))
		# else:
			# try:
				# self.logger.log("Error", "Error code {}! Update call for {} failed. See details - {}".format(r.status_code, data['_name'], r.json()))
				# print("Error code {}! Update call to {} failed.".format(r.status_code, url))
			# except Exception as e:
				# self.logger.log("Error", "Update call to {} failed. {} ERROR on args {}".format(data['_name'], type(e), e.args))

	def approve(self, uuid):
		self._validateAuth()
		self._validateApprovalAuth()
		url = self.MY_URL + "/{}({})/@approve".format(self.SCHEMA, uuid)
		if uuid is not None:
			try:
				r = requests.get(url, headers = self.ApprovalHEADER)
				if 200 <= r.status_code < 300:
					print("Approval success ({})!".format(uuid))
					self.logger.log("Msg", "Approval success ({})!".format(uuid))
				else:
					print("Approval failed ({})!".format(uuid))
					self.logger.log("Error", "Approval failed ({})!".format(uuid))
			except Exception as e:
				print("Approval failed ({})! {} ERROR on args {}.".format(uuid, type(e), e.args))
				self.logger.log("Error", "Approval failed ({})! {} ERROR on args {}.".format(uuid, type(e), e.args))
		else:
			print("UUID has not been passed.")
			self.logger.log("Error", "UUID has not been passed.")

	def validateOnSearch(self, term):
		search_result = self.search(term)
		if search_result is not None:
			full_result = self.getFull(search_result['uuid'])
			return self.validate(full_result)
		else:
			return "Search failed on {}".format(term)

	def uploadOnSearch(self, term):
		if type(term) == tuple:
			try:
				custom_code = str(term[1])
				code_sys = str(term[2])
				term = str(term[0])
			except Exception as e:
				print("Non-valid tuple '{}' used".format(term))
				self.logger.log("Error", "'{}' is a non-valid tuple. {} ERROR on args {}".format(term, type(e), e.args))
		else:
			custom_code = None
		search_result = self.search(term)
		
		if search_result is not None:
			full_result = self.getFull(search_result['uuid'])
			# val_result = self.validate(full_result) # Not sure if necessary. May be duplicated action if SRS is already validating on the backend.
			# if val_result is not None:
			if full_result is not None:
				if custom_code is not None:
					code_data = self._buildCode(
						code_id = custom_code,
						code_system = code_sys,
						)
					full_result['codes'].append(code_data)
				
				publicUUID = self._buildCode(
						code_id = full_result['approvalID'],
						code_system = "G-SRS UUID",
						url = "https://tripod.nih.gov/ginas/app/substance/{}".format(full_result['uuid'].split("-")[0]),
						# ref = [full_result['uuid']] # Must pass an array
						)
				full_result['codes'].append(publicUUID)
				try:
					del full_result['approvalID']
					self.upload(full_result)
				except:
					pass
				try:
					self.approve(full_result['uuid'])
				except:
					pass
					
				
			else:
				self.logger.log("Error", "Error retrieving full data for '{}'.".format(term))
				print("Error retrieving full data for '{}'.".format(term))
		else:
			self.logger.log("Error", "Error retrieving data for '{}'.".format(term))
			print("Error retrieving data for '{}'.".format(term))
		
	def bulkAction(self, action, bulkdata, workers = 25):
	## bulkdata should be a list composed of just string values or tuples
	## if it is tuples, the format should be (term, code, code_system)
	## e.g. In the case of NHPID data, the format is [('ingredient term', 'nid', 'NHPID'), ( , , ), ..]

		if action == "upload":
			operation = self.upload
			valid_action = True
		elif action == "upload_on_search":
			operation = self.uploadOnSearch
			valid_action = True
		else:
			valid_action = False
		
		if valid_action is True:
			if self.USERNAME is None or self.PASSWORD is None:
				self.authenticate()
			print("Executing {} jobs with {} workers in multithread".format(len(bulkdata), workers))
			self.logger.log("Msg", "Executing {} jobs with {} workers in multithread".format(len(bulkdata), workers))
			with multiprocessing.Pool(workers) as p:
				p.map(operation, bulkdata)
			print("Completed {} jobs".format(len(bulkdata)))
			self.logger.log("Msg", "Completed {} jobs".format(len(bulkdata)))
		else:
			print("{} is not a valid action".format(action))
