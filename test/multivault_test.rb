
require 'minitest/autorun'
require_relative '../lib/multivault.rb'

class TestMultiVault < Minitest::Test 

  def setup
	@userkeydir = '.mvtest'
	
	# create test key
	MVAULT.delete_key( userkeydir: @userkeydir )
	MVAULT.create_key( userkeydir: @userkeydir )
	
  end



end
