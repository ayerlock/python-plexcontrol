#!/usr/bin/python
# coding: utf-8
###--- Module Imports -----------------------------------------------------------------------------------------------------------
import	ConfigParser
from	urlparse			import	urlparse
from	urlparse			import	urljoin
#import	codecs
import	os, re, requests, signal, shutil, sys, time, traceback
import	logging, logging.handlers
from	plexapi		import server.PlexServer
#from	bs4					import	BeautifulSoup	as	bSoup
#from	collections			import	OrderedDict
###--- My Modules ---------------------------------------------------------------------------------------------------------------
#from	libosstd			import	fulldict, VerbDict, DataHandler, DirectoryCheck, DirectorySetup, FileCheck, AppendData, WriteData, FileHead, FileExt

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
	gap= ap.add_argument_group( 'authentication' )
	gap.add_argument( '-l',	'--login', 			action = 'store_true', 	default = False )
	gap.add_argument( 		'--user', 			action = 'store', 		dest = "username", 	metavar = "[username]" )
	gap.add_argument( 		'--pass', 			action = 'store', 		dest = "password", 	metavar = "[password]" )
	gap= ap.add_argument_group( 'logging' )
	gap.add_argument( 		'--loglevel', 		action = 'store', 		dest = "loglevel", 	metavar = "[logging level]", 	default = 'info', 	choices= ['crit', 'error', 'warn', 'notice', 'info', 'verbose', 'debug', 'insane'] )
	gap.add_argument( 		'--logfile', 		action = 'store', 		dest = "logfile", 	metavar = "[logfile]" )
	gap.add_argument(		'--debug', 			action = 'store_true' )
	gap.add_argument( '-v', '--verbose', 		action = 'count', 		default = 0 )

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
		servercfg['host'] = pConfig.get( server, host )
		servercfg['port'] = pConfig.get( server, port )
		servercfg['username'] = pConfig.get( server, username )
		servercfg['password'] = pConfig.get( server, password )
		
	return servercfg
###------------------------------------------------------------------------------------------------------------------------------
def main():
	global pArgs
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
		
###------------------------------------------------------------------------------------------------------------------------------
if __name__ == '__main__':
	main()
###------------------------------------------------------------------------------------------------------------------------------