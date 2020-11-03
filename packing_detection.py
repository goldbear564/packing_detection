# -*- coding: cp949 -*-
#apply UPACK
from __future__ import print_function
import json
import os
import os.path
import sys
import math
import pefile  
import time
import fnmatch
import re
import _winreg
import peutils 
import struct
from optparse import OptionParser
import glob
import win32pdh
import subprocess
import csv
import shutil

UNPACKING_LIST=['upx','mew','nspack','aspack','yoda\'s protector','packman','rlpack','beroexepacker','mpress']


		

class MY_PE_INFORMATION():
	def __init__(self):
		self.section_num=None
		self.section_list=[]
		self.EP_Section=None
		self.eop=None #Address of Entry Point
		self.File_Offset=None
		self.Byte_Size=None
		self.fb=None
		self.Eop_Flag=None
		self.dll=None
		self.antidbg=None

	def not_code_section(self):
		self.section_num=0
		self.EP_Section=0
		self.File_Offset=0
		self.Byte_Size=0
		self.fb=0
		self.antidbg=0
		self.Eop_Flag=False
		
class MY_PACKING_RESULT():
	def __init__(self,file_path):
		self.file_path=file_path
		self.file_name=os.path.basename(file_path)
		self.EP_name=None
		self.validPE=None
		self.entropy_wholefile=None
		self.entropy_pack_detection=None
		self.entropy_EP=None
		self.entropyEP_pack_detection=None
		self.packer=None
		self.packer_pack_detection=None
		self.WR=None
		self.WR_pack_detection=None
		self.Final_Pack_Detect=None
		self.pe_info=MY_PE_INFORMATION()
		self.error=None
		self.error_code=None
		self.unpack_avail=False
		self.upx=False
		

	def not_code_section(self):
		self.entropy_wholefile=0
		self.entropy_pack_detection=0
		self.entropy_EP=0
		self.entropyEP_pack_detection=0
		self.packer=""
		self.packer_pack_detection=0
		self.WR=0
		self.WR_pack_detection=0
		self.Final_Pack_Detect=True
	def final_pack_detection(self):
		if self.entropyEP_pack_detection==True or self.packer_pack_detection==True or self.WR_pack_detection==True:
			self.Final_Pack_Detect=True
		else:
			self.Final_Pack_Detect=False
		
		for unpack in UNPACKING_LIST:
			if self.packer and unpack.lower() in self.packer[0].lower():
				self.unpack_avail=True
			if self.packer and 'upx' in self.packer[0].lower():
				self.upx=True

def get_packer_signature(pe,userdb):
	print('==========get packer signatures=================')
	packer_name=""
	sig = peutils.SignatureDatabase(userdb)
	a =  sig.generate_section_signatures(pe,userdb)
	matches = sig.match_all(pe, ep_only=True)
	
	arr = []
	if matches is None:
		print('')
	
	elif matches:
		print(matches)
		for i in matches:
			#print("pacekr_siganature i is : ", i)
			if i not in arr:
				arr.append(i)
	return arr
	

def find_entry_point_section(pe, cur_result):
	eop_rva=cur_result.pe_info.eop
	for section in pe.sections:
		if section.contains_rva(eop_rva):
			return section
	return None

def entropy(fn):
	byteArr = map(ord,fn.read())
	filesize = len(byteArr)
	freqList = []
	freq1=0
	freq2=0
	ent=0.0
	try :
		for a in range(256): #IT Takes too long
			ctr=byteArr.count(a)
			freq=float(ctr)/filesize
			ent=ent+freq*math.log(freq,2)
	except ValueError:
		ent = 1
		


	ent=-ent
	bit_size = ent*filesize
	byte_size = (ent*filesize)/8
	return ent,bit_size,byte_size

def antidbg_detect(string_match):
	print('==============antidbg start=====================')
	antidbgapi = False
	antidbgs=string_match['antidbg']
	imp_import=[]
	array=[]
	pe.parse_data_directories()
	
	try:
		for entry in pe.DIRECTORY_ENTRY_IMPORT:
			print("import dll : ", entry.dll)
			for imp in entry.imports:
				print('\t',hex(imp.address),imp.name)
				imp_import.append(imp.name)	
		array = [c for c in imp_import if c in antidbgs]
		print("array : ",array)
		if array : antidbgapi = True
		print("antidbgapi : ", antidbgapi)
		
	except:
		print("GET IMPORT DLL/API FAIL!!")
	
		
	print('==============antidbg end=====================')
	return antidbgapi

def get_pe_information(cur_result):
#section number, Entry Point Section, eop, File_Offset, EP_Entropy, EP_Characteristic, file_ent, byte_size, fb, packed_or_not, packer_list,eop_flag	
	print('===================Start PE Analysis==============')
	cur_result.pe_info.section_num = pe.FILE_HEADER.NumberOfSections
	cur_result.pe_info.eop=pe.OPTIONAL_HEADER.AddressOfEntryPoint 
	cur_result.pe_info.EP_Section = find_entry_point_section(pe, cur_result)
	
	if not cur_result.pe_info.EP_Section: # Cant Found EP Sectoin
		print("fail to get entry point section")
		cur_result.pe_info.not_code_section()
		cur_result.not_code_section()
		return cur_result
		
	file_ent,bit_size,byte_size=entropy(fn)
	cur_result.entropy_wholefile=file_ent
	if 5.0<=file_ent<=6.85:
		cur_result.entropy_pack_detection=False
	else:
		cur_result.entropy_pack_detection=True
	
	#code_wat_eop=cur_result.pe_info.EP_Section.get_data(cur_result.pe_info.eop,10)
	cur_result.pe_info.dll=pe.is_dll()
	section_list=[]
	for section in pe.sections:
		name=""
		for c in section.Name:
			if c.isalnum():
				name+=c
		print('entropy of %s section : %f' % (name,section.get_entropy()))
		cur_result.pe_info.section_list.append(name)
		section_list.append(name)
		section_list.append(hex(section.VirtualAddress))
		section_list.append(hex(section.Misc_VirtualSize))
		section_list.append(section.SizeOfRawData)
		a='{:#x}'.format(section.Characteristics)
		
		section_size=section.VirtualAddress+section.Misc_VirtualSize
		if cur_result.pe_info.Eop_Flag==False or cur_result.pe_info.Eop_Flag==None:
			if section.VirtualAddress<=cur_result.pe_info.eop<section_size:
				cur_result.EP_name=name
				cur_result.entropy_EP=section.get_entropy()
				if 5.0<=cur_result.entropy_EP<=6.85:
					cur_result.entropyEP_pack_detection=False
				else:
					cur_result.entropyEP_pack_detection=True
				cur_result.WR=a
				cur_result.pe_info.File_Offset=cur_result.pe_info.eop-section.VirtualAddress+section.PointerToRawData
				if(a[2] == '8' or a[2]=='c' or a[2]=='e'):
					cur_result.WR_pack_detection=True
				else:
					cur_result.WR_pack_detection=False
				cur_result.pe_info.Eop_Flag=True
				
	#print ('Entry Point Section: ', cur_result.pe_info.EP_Section)
	print ('Entry Point Section Name: ', cur_result.EP_name)
	print ('Entropy of Whole File ', cur_result.entropy_wholefile)
	packer=get_packer_signature(pe, userdb)
	if len(packer)>0:
		packer_name=packer[-1][-1]
		if packer_name :		
			if 'Microsoft' in packer_name[0]:
				ansr_sig='no'
				packer_detect=False
			elif 'Wise' in packer_name[0]:
				ansr_sig='no'
				packer_detect=False
			elif 'Armadillo' in packer_name[0]:
				ansr_sig='no'
				packer_detect=False
			elif 'Delphi' in packer_name[0]:
				ansr_sig='no'
				packer_detect=False
			elif 'WinZip' in packer_name[0]:
				ansr_sig='no'
				packer_detect=False
			elif 'Symantec' in packer_name[0]:
				ansr_sig='no'
				packer_detect=False
			elif 'MS' in packer_name[0]:
				ansr_sig='no'
				packer_detect=False
			elif 'Borland' in packer_name[0]:
				ansr_sig='no'
				packer_detect=False
			elif 'VC8' in packer_name[0]:
				ansr_sig='no'
				packer_detect=False
			else:
				ansr_sig="Yes"
				packer_detect = True	
	else :
		ansr_sig="no"
		packer_detect = False
		packer_name=""
	print(packer_name,packer_detect)
	cur_result.packer=packer_name
	cur_result.packer_pack_detection=packer_detect
	
	antidbg=antidbg_detect(string_match)
	if antidbg:
		cur_result.pe_info.antidbg=antidbg
	return cur_result
		
def unpack_processing(cur_pe):
	print('==============Start Unpacking=====================')
	dir=_ROOT+'/unpacked/upx'
	print("cur_pe.filename: %s cur_pe.filepath: %s" % (cur_pe.file_name,cur_pe.file_path))
	files=os.listdir(dir)
	print(files)
	file_name2='u_'+cur_pe.file_name
	file_path2=cur_pe.file_path
	
	for i in range(len(files)):
		a=0
		while(1):
			if file_name2 in files:
				a+=1
				file_name2='('+str(a)+')'+file_name
			else:
				break
	upx_unpack='upx.exe -d -o ./unpacked/upx/%s %s' % (file_name2, file_path2)
	#print(upx_unpack)
	a=subprocess.call(upx_unpack,shell=True)
	if a!=0:
		print("upx.exe ERROR!!!")
	print('==============End Unpacking=======================\n')
	
	
def main(file_path):
	global fn,pe,userdb,string_match,file_name,_ROOT
	fn=open(file_path,'rb')
	print('File path: %s' % file_path)
	file_name=os.path.basename(file_path)
	print('File name: %s' % file_name)
	_ROOT = os.path.abspath(os.path.dirname(__file__))
	def get_data(path):
		return os.path.join(_ROOT,'signatures',path) # for detect anti-dbg api
	fn_stringsmatch = get_data('stringsmatch.json')
	with open(fn_stringsmatch) as antidbg_sig:
		string_match=json.load(antidbg_sig)
	def get_userdb(path):
		return os.path.join(_ROOT,'signatures',path)
	userdb=get_userdb('userdb_up.txt')
	cur_result=MY_PACKING_RESULT(file_path)
	#cur_result=cur_result.path_setting(file_path)
	try:
		pe=pefile.PE(file_path)
		cur_result.validPE=True
		#cur_result.set_validPE(True)
	except pefile.PEFormatError as err:
		cur_result.validPE=False
		#cur_result.set_validPE(False)
		return cur_result
	cur_result=get_pe_information(cur_result)
	
	
	if cur_result.pe_info.Eop_Flag==False:
		print("Code Section Not Found")
		return cur_result
	
	return cur_result
		
'''
ver 0.2
add function
 - save csv file
'''

if __name__=='__main__':
	print("--------------")
	if len(sys.argv)==1:
		print ('%s <PE_Filename or Directory_Name>' % sys.argv[0])
		print ('%s -csv csv_file_name <PE_Filename or Directory_Name>' % sys.argv[0])
	elif len(sys.argv)==2 and sys.argv[1]=="csv":
		print ('%s <PE_Filename or Directory_Name>' % sys.argv[0])
		print ('%s -csv csv_file_name <PE_Filename or Directory_Name>' % sys.argv[0])
	elif len(sys.argv)==3 and sys.argv[1]=="csv":
		print ('%s -csv csv_file_name <PE_Filename or Directory_Name>' % sys.argv[0])
	else:
		detection_PE=[]
		detection_notPE=[]
		fail_list=[]
		i=1
		csv_flag=False
		
		if sys.argv[1]=='-csv':
			csv_flag=True
			i=3
			
		for x in range(i,len(sys.argv)):
			if x==0:
				pass
			else:
				#print("%s" % sys.argv[x])
				#print("%d" % len(sys.argv))
				sys_file_path=sys.argv[x]
				FileList=glob.glob(sys_file_path)
				#print(FileList) #print all path of sys.argv[i]
				for file in FileList:
					if os.path.isdir(file):
						continue
					print('==================================================')
					print('=====================Start Main===================')
					try:
						pe_result=main(file)
					except MemoryError:
						pe_result.error="MemoryError occur"
						pe_result.error_code=MemoryError
						print(pe_result.error)
					except WindowsError:
						pe_result.error="WindwosError occur"
						pe_result.error_code=WindwosError
						
					print('==================================================')
					print('=====================End Main===================\n')
					if pe_result.validPE==True:
						detection_PE.append(pe_result)
						pe_result.final_pack_detection()
						if pe_result.Final_Pack_Detect==True:
							file_name=os.path.basename(file)
							
							#shutil.copy(src+file_name,dst_packed)
						else:
							file_name=os.path.basename(file)
							#shutil.copy(src+file_name,dst_notpacked)
						if pe_result.upx:
							unpack_processing(pe_result)
					else:
						detection_notPE.append(pe_result)
		if csv_flag==True:
			with open(sys.argv[2]+".csv","w") as csvfile:
				writer=csv.writer(csvfile,delimiter=',')
				writer.writerow(['File_Path','Packing','Packer','Unpacking'])
				for a in detection_PE:
					writer.writerow([a.file_path, a.Final_Pack_Detect,a.packer,a.unpack_avail])
					print('file path: %s ==> Packing: %s' %(a.file_path,a.Final_Pack_Detect))					
				if detection_notPE:
					print("-------NOT Valid PE file--------")
					for i in detection_notPE:
						print('file path: %s'%i.file_path)
		else:
			for i in detection_PE:
				print('file path: %s ==> Packing: %s, Packer: %s, Unpacking: %s' %(i.file_path,i.Final_Pack_Detect,i.packer,i.unpack_avail))
			if detection_notPE:
				print("-------NOT Valid PE file--------")
				for i in detection_notPE:
					print('file path: %s'%i.file_path)