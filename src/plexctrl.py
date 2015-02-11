#!/usr/bin/python3
# coding: utf-8
###--- Module Imports -----------------------------------------------------------------------------------------------------------
try:
	import	configparser
except:
	import	ConfigParser		as configparser

try:
	import	http.cookiejar		as cookielib
except:
	import	cookielib

try:
	from	urllib.parse		import	urlparse		as	urlparse
	from	urllib.parse		import	urljoin			as	urljoin
except:
	from	urlparse			import	urlparse
	from	urlparse			import	urljoin
	
try:
	from	io					import	StringIO
except:
	from	StringIO			import	StringIO

import	os, re, requests, signal, shutil, sys, time, traceback
import	logging, logging.handlers
#from	plexapi.server		import	PlexServer
from	plexapi.myplex		import	MyPlexUser as PlexUser
from	lxml				import	etree	as letree
from	xml					import	etree	as xetree

###--- Function Definitions -----------------------------------------------------------------------------------------------------
def argparser():
	global pArgs
	import argparse

	ap = argparse.ArgumentParser( description = 'A web image grabber.', prog = os.path.basename( re.sub( ".py", "", sys.argv[0] ) ) )
	ap.add_argument( '-s', 	'--server', 		action = 'store', 		dest = "server", 	metavar = "[server]" )
	ap.add_argument( '-p', 	'--port', 			action = 'store', 		dest = "port", 		metavar = "[server port]" )
	gap = ap.add_argument_group( 'standard functionality' )
	gap.add_argument( 		'--version', 		action = 'version', 	version = '%(prog)s 0.1' )
	gap.add_argument( 		'--program', 		action = 'store', 		dest = "program",	metavar = "[program]", 	default = os.path.basename( re.sub( ".py", "", sys.argv[0] ) ) )
	gap.add_argument(		'--search', 		action = 'store', 		dest = "search", 	metavar = "[search]" )
	gap.add_argument( 		'--config', 		action = 'store', 		dest = "config", 	metavar = "[config]", 	default = 'default.cfg' )
	gap.add_argument( 		'--xml',	 		action = 'store', 		dest = "xmlparser", metavar = "[XML Parser]", 	default = 'lxml' )
	gap= ap.add_argument_group( 'authentication' )
	gap.add_argument( '-l',	'--login', 			action = 'store_true', 	default = False )
	gap.add_argument( 		'--user', 			action = 'store', 		dest = "username", 	metavar = "[username]" )
	gap.add_argument( 		'--pass', 			action = 'store', 		dest = "password", 	metavar = "[password]" )
	gap= ap.add_argument_group( 'logging' )
	gap.add_argument( 		'--loglevel', 		action = 'store', 		dest = "loglevel", 	metavar = "[logging level]", 	default = 'info', 	choices= ['crit', 'error', 'warn', 'notice', 'info', 'verbose', 'debug', 'insane'] )
	gap.add_argument( 		'--logfile', 		action = 'store', 		dest = "logfile", 	metavar = "[logfile]" )
	gap.add_argument(		'--debug', 			action = 'store_true' )
	gap.add_argument( '-v', '--verbose', 		action = 'count', 		default = 0 )
	gap= ap.add_argument_group( 'operations' )
	gap.add_argument(		'--clients', 		action = 'store_true' )
	gap.add_argument(		'--recent', 		action = 'store_true' )
	gap.add_argument(		'--myplex', 		action = 'store_true' )

	try:
		pArgs = ap.parse_args()
	except:
		success = False
	else:
		success = True
		
	initLog( pArgs.loglevel )
	logger = logging.getLogger( __name__ )
	
	if success:
		return pArgs
	else:
		sys.exit( 2 )
###------------------------------------------------------------------------------------------------------------------------------
def initLog( LLevel ):
	logger = logging.getLogger( __name__ )
	LogLevels= {'crit':logging.CRITICAL,
				'error':logging.ERROR,
				'warn':logging.WARNING,
				'info':logging.INFO,
				'debug':logging.DEBUG }
	LogLevel										= LogLevels.get( LLevel, logging.NOTSET )
	logger.setLevel( LogLevel )
	LogFormat										= '(%(asctime)-11s)  :%(levelname)-9s:%(funcName)-13s:%(message)s'
	if ( len( logger.handlers ) == 0 ):
		try:
			Colorize								= __import__( 'logutils.colorize', fromlist = ['colorize'] )
			LogHandler								= Colorize.ColorizingStreamHandler()
			LogHandler.level_map[logging.DEBUG]		= ( None, 'blue', False )
			LogHandler.level_map[logging.INFO]		= ( None, 'green', False )
			LogHandler.level_map[logging.WARNING]	= ( None, 'yellow', False )
			LogHandler.level_map[logging.ERROR]		= ( None, 'red', False )
			LogHandler.level_map[logging.CRITICAL]	= ( 'red', 'white', False )
		except ImportError:
			LogHandler	= logging.StreamHandler()
	else:
		LogHandler	= logging.StreamHandler()
	LogHandler.setFormatter( logging.Formatter( LogFormat, datefmt = '%I:%M:%S %p' ) )
	logger.addHandler( LogHandler )
###------------------------------------------------------------------------------------------------------------------------------
def ReadConfig():
	logger = logging.getLogger( __name__ )
	
	home = os.environ["HOME"]
	cfgDirectory = ( "%s/.%s" % ( home, pArgs.program ) )
	cfgFile = os.path.join( cfgDirectory, pArgs.config )
	
	# Check for configuration file.
	if os.path.isfile( cfgFile ):
		logger.debug( "Reading Configuration File: %s" % ( cfgFile ) )
	else:
		logger.error( "No configuration file found!" )
		# Set exit status '1' upon failure and exit.
		sys.exit( 1 )

	config = configparser.ConfigParser()
	config.read( cfgFile )
		
	if pArgs.verbose > 3:
		logger.debug( config.sections() )
		
	return config
###------------------------------------------------------------------------------------------------------------------------------
def SetServer( pConfig ):
	logger = logging.getLogger( __name__ )
	
	servercfg = dict()
	
	# Check if there was a default Plex server set via the command line or configuration file.
	if pArgs.server is None:
		if "global" in pConfig.sections():
			server = pConfig.get( 'global', 'defaultserver' )
			logger.debug( "Setting server:\t%s" % server )
		else:
			logger.error( "No [global] section in configuration file and --server was not passed." )
			# Set exit status '2' upon failure and exit.
			sys.exit( 2 )
	else:
		server = pArgs.server
		logger.debug( "Setting server:\t%s" % server )
	
	# Check for designated [server] section of configuration file.
	if not server in pConfig.sections():
		logger.error( "No [%s] section in configuration file." % ( pServer ) )
		# Set exit status '3' upon failure and exit.
		sys.exit( 3 )
	else:
		servercfg['server'] = server
		servercfg['host'] = pConfig.get( server, 'host' )
		servercfg['port'] = pConfig.get( server, 'port' )
		servercfg['username'] = pConfig.get( server, 'username' )
		servercfg['password'] = pConfig.get( server, 'password' )
		
	return servercfg
###------------------------------------------------------------------------------------------------------------------------------
def clients( plex ):
	logger = logging.getLogger( __name__ )

	for client in plex.clients():
		logger.info( client.name )
###------------------------------------------------------------------------------------------------------------------------------
def DictPrint( data, Name = None, tabbed = False ):
	logger = logging.getLogger( __name__ )
	if tabbed:
		prestring = '\t'
	else:
		prestring = ''
	for key in data.keys():
		if key == "cookiejar":
			if Name is None:
				logger.warn( "%sKey: %s\tValue: %s" % ( prestring, key, "[CookieJar]" ) )
			else:
				logger.warn( "%s%s['%s']\tValue: %s" % ( prestring, Name, key, "[CookieJar]" ) )
		elif key == "pagecontent":
			if Name is None:
				logger.warn( "%sKey: %s\tValue: %s" % ( prestring, key, "[PageContent]" ) )
			else:
				logger.warn( "%s%s['%s']\tValue: %s" % ( prestring, Name, key, "[PageContent]" ) )
		else:
			if Name is None:
				logger.warn( "%sKey: %s\tValue: %s" % ( prestring, key, data[key] ) )
			else:
				logger.warn( "%s%s['%s']\tValue: %s" % ( prestring, Name, key, data[key] ) )
###------------------------------------------------------------------------------------------------------------------------------
def pageencode( pagedata ):
	try:
		pagedata = str( pagedata, errors = 'ignore' )
	except:
		pagedata = str( pagedata )
	try:
		pagedata = pagedata.encode( 'ascii', 'ignore' )
	except:
		pagedata = pagedata
	return pagedata
###------------------------------------------------------------------------------------------------------------------------------
def getURL( url ):
	logger = logging.getLogger( __name__ )
	
	global rSession
	CookieJar = cookielib.CookieJar()
	timeout = '30'
	stream = False

	#url = "http://apollo.ayercraft.net:32400/library/recentlyAdded"
	url = "http://apollo.ayercraft.net:32400/library/sections/7/recentlyAdded"

	pagecontent = None
	reqheaders = dict()
	respheaders = dict()

	reqheaders['accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
	reqheaders['accept-language'] = 'en-US,en;q=0.5'
	reqheaders['accept-encoding'] = 'gzip,deflate'
	reqheaders['DNT'] = '1'
	reqheaders['connection'] = 'keep-alive'
	reqheaders['user-agent'] = 'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:29.0) Gecko/20100101 Firefox/29.0'
	
	try:
		response = rSession.get( url, headers = reqheaders, cookies = CookieJar, timeout = float( timeout ) )
	except requests.exceptions.HTTPError as exc:
		logger.error( "(HTTP Error): %s\tURL: " % ( exc, url ) )
	except requests.exceptions.ConnectionError as exc:
		logger.error( "(Connection Error) %s\tURL: %s" % ( exc, url ) )
	except requests.exceptions.Timeout as exc:
		logger.error( "(Request Timeout Error) %s\tURL: %s" % ( exc, url ) )
	else:
		isCType = False
		if response.status_code == requests.codes.ok:
			if pArgs.verbose > 3:
				logger.error( "Good Status Code:\t%s" % ( response.status_code ) )
				DictPrint( response.headers, Name = 'Response Header' )
			for key in response.headers.keys():
				if key == "Content-Type":
					ctype = "Content-Type"
					isCType = True
					logger.debug( "Header: %s\tValue: %s" % ( key, response.headers[key].strip() ) )
				elif key == "content-type":
					ctype = "content-type"
					isCType = True
					logger.debug( "Header: %s\tValue: %s" % ( key, response.headers[key].strip() ) )
				respheaders[key] = response.headers[key].strip()
			if isCType:
				if ( "text/html" in response.headers[ctype].strip() ) or ( "text/xml" in response.headers[ctype].strip() ) or ( "text/javascript" in response.headers[ctype].strip() ):
					if pArgs.verbose > 3:
						logger.debug( "Page returned content type(A):\t%s" % response.headers[ctype].strip() )
				else:
					if pArgs.verbose > 3:
						logger.debug( "Page returned content type(B):\t%s" % response.headers[ctype].strip() )
		else:
			logger.error( "Error retrieving url: %s" % ( url ) )
			logger.error( "\tError:\tBad Status Code:\t%s" % ( response.status_code ) )
	return response
###------------------------------------------------------------------------------------------------------------------------------
def recentlyAdded( servercfg ):
	logger = logging.getLogger( __name__ )

	url = "http://apollo.ayercraft.net:32400/library/sections/7/recentlyAdded"
	response = getURL( url )
	
	if pArgs.xmlparser == "lxml":
		xmlContent = letree.fromstring( response.text.encode('utf8') )
		parser = letree.XMLParser( ns_clean = True )
		tree = letree.parse( StringIO( xmlContent ), parser )
	elif pArgs.xmlparser == "xml":
		xmlContent = xetree.ElementTree.fromstring( response.text.encode('utf8') )
		parser = xetree.XMLParser( ns_clean = True )
		tree = xetree.parse( StringIO( xmlContent ), parser )
		
	for element in xmlContent.iter():
		if element.tag == "Directory":
			mptitle = element.get( 'parentTitle' )
			mstitle = element.get( 'title' )
			mtype = element.get( 'type' )
			logger.info("Title: %s\tType: %s\tSubTitle: %s" % ( mptitle, mstitle, mtype ) )
		if element.tag == "Video":
			vtype = element.get( 'type' )
			if vtype == "episode":
				vptitle = str( element.get( 'grandparentTitle' ) ).encode('utf-8').strip()
				vseason = str( element.get( 'parentIndex' ) ).encode('utf-8').strip()
				vepisode = str( element.get( 'index' ) ).encode('utf-8').strip()
				vetitle = unicode( element.get( 'title' ) ).encode( 'ascii', 'replace' )
				logger.info("Title: %s\tSeason: %s\tEpisode: %s\tTitle: %s" % ( vptitle, vseason, vepisode, vetitle ) )
	
	#for elem in xmlContent:
	#	logger.info( xmlContent.keys() )
	
	#root = etree.fromstring( content )
	#parser = etree.XMLParser( ns_clean = True )
	#tree = etree.parse( StringIO( content ), parser )
	#for element in root.iter():
	#	if element.tag == "Directory":
	#		mptitle = element.get( 'parentTitle' )
	#		mstitle = element.get( 'title' )
	#		mtype = element.get( 'type' )
	#		print("Title: %s\tType: %s\tSubTitle: %s" % ( mptitle, mstitle, mtype ) )
	#	if element.tag == "Video":
	#		vtype = element.get( 'type' )
	#		if vtype == "episode":
	#			vptitle = str( element.get( 'grandparentTitle' ) ).encode('utf-8').strip()
	#			vseason = str( element.get( 'parentIndex' ) ).encode('utf-8').strip()
	#			vepisode = str( element.get( 'index' ) ).encode('utf-8').strip()
	#			vetitle = unicode( element.get( 'title' ) ).encode( 'ascii', 'replace' )
	#			print("Title: %s\tSeason: %s\tEpisode: %s\tTitle: %s" % ( vptitle, vseason, vepisode, vetitle ) )
###------------------------------------------------------------------------------------------------------------------------------
def myPlex( servercfg ):
	logger = logging.getLogger( __name__ )
	
	from plexapi.myplex import MyPlexUser
	from plexapi.server import PlexServer
	
	user = MyPlexUser( servercfg['username'], servercfg['password'] )
	for key in user.keys():
		logger.debug( "\tKey: %s\tValue: %s" % ( key, user[key] ) )
		
	server = user.getServer( servercfg['server']).connect
	
	for server in user.servers():
		logger.info( "Server: %s" % ( server ) )
		
	plex = PlexServer( servercfg['host'], servercfg['port'], user['authenticationToken'] )
	for section in plex.library.sections():
		logger.info( "Section: %s" % ( section.title ) )
###------------------------------------------------------------------------------------------------------------------------------
def main():
	global pArgs
	global rSession
	logger = logging.getLogger( __name__ )
	pArgs = argparser()
	
	if pArgs.verbose > 3:
		logger.debug( pArgs )
		
	pConfig = ReadConfig()
	
	servercfg = SetServer( pConfig )
	if pArgs.verbose > 3:
		logger.debug( "Server:\t%s:%s" % ( servercfg['host'], servercfg['port'] ) )
		logger.debug( "Username:\t%s" % ( servercfg['username'] ) )
		logger.debug( "Password:\t%s" % ( servercfg['password'] ) )

	#user = PlexUser( servercfg['username'], servercfg['password'] )
	#plex = user.getServer( servercfg['server'] ).connect()

	rSession = requests.session()
	
	if pArgs.clients:
		clients( plex )
	elif pArgs.recent:
		content = recentlyAdded( servercfg )
	elif pArgs.myplex:
		content = myPlex( servercfg )
###------------------------------------------------------------------------------------------------------------------------------
if __name__ == '__main__':
	main()
###------------------------------------------------------------------------------------------------------------------------------
