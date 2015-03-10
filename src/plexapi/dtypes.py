# coding: utf-8

class ddict( dict ):
	def __init__( self, **kwargs ):
		keys = kwargs.keys()
		for key in keys:
			self[key] = kwargs[key]
	###---------------------------------------------------------------------
	def __delattr__( self, key ):
		self.pop( key )
	###---------------------------------------------------------------------
	def __getattr__( self, key ):
		return self[key]
	###---------------------------------------------------------------------
	def __hasattr__( self, key ):
		if self.has_key( key ):
			return True
		else:
			return False
	###---------------------------------------------------------------------
	def __setattr__( self, key, value ):
		self[key] = value
	###---------------------------------------------------------------------
