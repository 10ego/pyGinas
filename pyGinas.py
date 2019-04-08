# version 0.6
import requests
# import asyncio
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
			self.logfile = 'log/{}.log'.format(logfile)
			# self.logfile_uploads = 'log/{}_uploads.log'.format(logfile)
		except IOError as exception:
			raise IOError('%s: %s' % (path, exception.strerror))
		return None
	
	def log(self, message):
		timestamp = datetime.strftime(datetime.now(), "%Y-%m-%d %H:%M:%S (%z)")
		with open(self.logfile, type, 'a+') as log:
			log.write('[{}] [{}] {}'.format(timestamp, type, message))
			log.write('\n\n')
	# def logUploads(self, message):
		# timestamp = datetime.strftime(datetime.now(), "%Y-%m-%d %H:%M:%S (%z)")
		# with open(self.logfile_uploads, 'a+') as log:
			# log.write('[{}] {}'.format(timestamp, message))
			# log.write('\n\n')
			
class API():
	def __init__(self):
		self.BASE_URL = "https://tripod.nih.gov/ginas/app/api/v1"
		self.MY_URL = "https://srs.hres.ca/ginas/app/api/v1"
		self.USERNAME = None
		self.PASSWORD = None
		self.logger = pyGinasLogger('pyGinas')
		self.SCHEMA = None
	
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
	
	def setSRS(self, uri):
		self.MY_URL = uri
	
	def setSchema(self, schema):
		self.SCHEMA = schema
		self.logger.log("Msg", "Schema set to '{}'".format(self.SCHEMA))
	
	def _buildCode(self, code_id, code_system, ref=[], self_ref="", type = "PRIMARY",  deprecated = False, access=[]):
		
		code = {}
		code['_self'] = self_ref  # Self link to reference the code
		code['code'] = str(code_id)
		code['codeSystem'] = code_system
		code['type'] = type
		code['deprecated'] = deprecated
		code['references'] = ref
		code['access'] = access
		code['uuid'] = str(uuid4()) # Must generate a new UUID for each new entry
		
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
		
	def validateSchema(self):
		if self.SCHEMA is None:
			raise ValueError("Schema is set to None.")
			self.logger.log("Error", "No schemas set.")
		elif self.SCHEMA in ['references', 'edits', 'substances', 'structures', 'scheduledjobs', 'backups', 'xrefs', 'codes', 'values', 'vocabularies', 'keywords', 'names', 'payload', 'jobs']:
			self.logger.log("Msg", "Schema set to {}."format(self.SCHEMA))
			pass
		else:
			raise ValueError('{} is not a supported schema'.format(self.SCHEMA))
			self.logger.log("Error", "{} is not a supported schema".format(self.SCHEMA))
	def search(self, term):
		self.validateSchema()
		if type(term) is str:
			query_url = self.BASE_URL + "/{}/search?q={}".format(self.SCHEMA, term)
			r = requests.get(query_url)
			if 200 <= r.status_code < 300:
				result = r.json()['content']
				
				if result == []:
					print("No results found for '{}'.".format(term))
					self.logger.log("Warning", "No results found for '{}'.".format(term))
				else:
					name = result[0]['_name']
					if name.lower() != term.lower():
							print("Exact match not found for '{}'. Returning next best match ({}).".format(term, name))
							self.logger.log("Warning", "Exact match not found for '{}'. Returning next best match ({}).".format(term, name))
					else:
						print("Exact match found for '{}'.".format(term))
						self.logger.log("Msg", "Exact match found for '{}'."format(term))
					return result[0]
			else:
				self.logger.log("Error", "Error code {}! Search call failed for '{}'.".format(r.status_code, term))
				print("Error", "Error code {}! Search call failed for '{}'.".format(r.status_code, term))
		else:
			self.logger.log("Error", "Search call on '{}' failed. ERROR: '{}' is an unacceptable data type.".format(term, type(term)))
			print("Error", "Search call on '{}' failed. ERROR: '{}' is an unacceptable data type.".format(term, type(term)))
		return None
	
	def getFull(self, uuid):
		self.validateSchema()
		url = self.BASE_URL + "/{}({})?view=full".format(self.SCHEMA, uuid)
		r = requests.get(url)
		if 200 <= r.status_code < 300:
			return r.json()
			self.logger.log("Msg", "Retrieved full data from uuid: '{}'".format(uuid))
		else:
			self.logger.log("Error", "Error code {}! Search call failed for '{}' failed.".format(r.status_code, term))
			print("Error", "Error code{}! Search call to '{}' failed.".format(r.status_code, url))
			
		return None
	
	def validateThis(self, data):
		data = data.copy()
		del data['approvalID']
		yield data
	
	def validate(self, data):
		self.validateSchema()
		if self.USERNAME == None or self.PASSWORD == None:
			self.authenticate()
		url = self.MY_URL + "/{}/@validate".format(self.SCHEMA)
		if 'approvalID' in data:
			data = next(self.validateThis(data))
		r = requests.post(url = url, headers=self.HEADER, data = json.dumps(data))
		if 200 <= r.status_code < 300:
			return r.json()
		else:
			try:
				self.logger.log("Error", "Error code {}! Validation call for '{}' failed. See details - {}".format(r.status_code, data['_name'], r.json()))
				print("Error code {}! Validation call for {} failed.".format(r.status_code, data['_name']))
			except Exception as e:
				self.logger.log("Error", "Error code {}! Validation call for '{} 'failed. {} ERROR on args {}. See details - {}".format(r.status_code, data['_name'],type(e), e.args, r.json()))
		return None
		
	def upload(self, data):
		self.validateSchema()
		if self.USERNAME == None or self.PASSWORD == None:
			self.authenticate()
		url = self.MY_URL + "/{}".format(self.SCHEMA)
		r = requests.post(url = url, headers = self.HEADER, data = json.dumps(data))
		if 200 <= r.status_code < 300:
			self.logger.log("Msg", "Upload success ({})!".format(data['_name']))
			print("Upload success ({})!".format(data['_name']))
		else:
			try:
				self.logger.log("Error", "Error code {}! Upload call for '{}' failed. See details - {}".format(r.status_code, data['_name'], r.json()))
				print("Error code {}! Upload call for '{}' failed.".format(r.status_code, data['_name']))
			except Exception as e:
				self.logger.log("Error", "Error code {}! Upload call for '{}' failed. {} ERROR on args {}.".format(r.status_code, data['_name'], type(e), e.args))
	
	def update(self, data, code_data = None): # custom_code should be dictionary output of self._buildCode()
		self.validateSchema()
		if self.USERNAME == None or self.PASSWORD == None:
			self.authenticate()
		if code_data is not None:
			data['codes'].append(code_data)
		url = self.MY_URL + "/{}".format(self.SCHEMA)
		r = requests.put(url = url, headers = self.HEADER, data = json.dumps(data))
		if 200 <= r.status_code < 300:
			self.logger.log("Msg", "Update success ({})!".format(data['_name']))
			print("Update success ({})!".format(data['_name']))
		else:
			try:
				self.logger.log("Error", "Error code {}! Update call for {} failed. See details - {}".format(r.status_code, data['_name'], r.json()))
				print("Error code {}! Update call to {} failed.".format(r.status_code, url))
			except Exception as e:
				self.logger.log("Error", "Update call to {} failed. {} ERROR on args {}".format(data['_name'], type(e), e.args))
			
	def validateOnSearch(self, term):
		if self.USERNAME == None or self.PASSWORD == None:
			self.authenticate()
		search_result = self.search(term)
		if search_result != None:
			full_result = self.getFull(search_result['uuid'])
			return self.validate(full_result)
						
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
		if self.USERNAME == None or self.PASSWORD == None:
			self.authenticate()
		search_result = self.search(term)
		if search_result != None:
			full_result = self.getFull(search_result['uuid'])
			if custom_code != None:
				code_data = self._buildCode(
					code_id = custom_code,
					code_system = code_sys
					)
				# *** Validate code uuid collision ***
				
			else:
				code_data = None
			val_result = self.validate(full_result)
			if val_result != None and val_result['valid'] is True:
				full_result_copy = full_result.copy()
				try:
					del full_result['approvalID']
				except:
					pass
				try:
					self.upload(full_result)
					self.update(full_result_copy, code_data)
				except:
					pass	
	def bulkAction(self, action, bulkdata, multithread=False):
	## bulkdata should be a list composed of just string values or tuples
	## if it is tuples, the format should be (term, code, code_system)
	## e.g. In the case of NHPID data, the format is [('ingredient term', 'nid', 'NHPID'), ( , , ), ..]
		global counter
		counter = 0
		
		if action == "upload":
			operation = self.upload
			valid_action = True
			
		elif action == "upload_on_search":
			operation = self.uploadOnSearch
			valid_action = True
		else:
			valid_action = False
		
		if valid_action is True:
			if self.USERNAME == None or self.PASSWORD == None:
				self.authenticate()
			if multithread is True:
				print("Executing {} jobs in multithread".format(len(bulkdata)))
				self.logger.log("Msg", "Executing {} jobs in multithread".format(len(bulkdata)))
				# async def main(jobs):
					# global counter
					# loop = asyncio.get_event_loop()
					# futures = [
						# loop.run_in_executor(
							# None,
							# operation,
							# i
							# )
						# for i in jobs
					# ]
					# for response in await asyncio.gather(*futures):
						# counter+=1
						# print("Completed {} of {} jobs".format(counter, len(jobs)))
				# loop = asyncio.get_event_loop()
				# loop.run_until_complete(main(bulkdata))
				with multiprocessing.Pool(30) as p:
					p.map(operation, bulkdata)
				
			else:
				print("Executing {} jobs in singlethread".format(len(bulkdata)))
				self.logger.log("Msg", "Executing {} jobs in singlethread".format(len(bulkdata)))
				for data in bulkdata:
					operation(data)
					counter+=1
			print("Completed {} of {} jobs".format(counter, len(bulkdata)))
			self.logger.log("Msg", "Completed {} of {} jobs".format(counter, len(bulkdata)))
