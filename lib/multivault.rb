# jeroen vriesman <jeroen.vriesman@root-it.biz>

# implementation of a multu-user access vault
# access is based on "having the right private key", together with a username
# two types of users: reader and owners
# readers can read the vault
# owners can write the vault (that includes adding, deleting, promoting and demoting users)
# new users need to make a request to an owner to gain access to the vault (the request is a signature of the validation key + public key)

# private keys have length 4096
# a signature is a private key encrypted SHA256 digest (or any other signature digest)

require 'openssl'
require 'json'
require 'hashr'
require 'base64'

# setting defaults (todo: other ciphers and digests are untested)
DEFAULT_CRYPTOSET = {
  :signkey_cipher => 'aes-256-cbc',
  :data_cipher => 'aes-256-cbc',
  :signkey_digest => 'sha256',
  :data_digest => 'sha256',
  :valkey_digest => 'sha256',
  :vaultinfo_digest => 'sha256'
}

DEFAULT_DATA = 'EMPTY'

# extend Hash with methods to produce repeatble and consistant digests
class Hash

  # iterate over all keys and yield the key + a digest of the value and 
  def allkeys_valdigest( options = { :digest => DEFAULT_CRYPTOSET[ :vaultinfo_digest ] } )
    each_key do |key|
      if self[ key ].respond_to? ( :each )
        yield key.to_s
        self[ key ].allkeys_valdigest{ |out| yield out }
      else
        # concatenate key and value
        yield key.to_s + self[ key ]
      end
    end
  end
  
  def digestable( options = { :digest => DEFAULT_CRYPTOSET[ :vaultinfo_digest ] } )
    # collect the keys + value digests
    kdgs = []
    allkeys_valdigest( :digest => options[ :digest ] ) { |kdg| kdgs << kdg }
    # sort them, because the order of a hash is unspecified, concatenate for the digest
    kdgs.sort.join
  end
  
end

# this loads data into hashr, either from a file or from json data
class PreVault < Hashr

  def initialize( source = {} )
    @original_filename = source[ :file ]
    super( JSON.parse( IO.read( source[ :file ] ) ) ) if not source[ :file ].nil?
    super( JSON.parse( source[ :json ] ) ) if not source[ :json ].nil?
    super( source ) if source[ :file ].nil? and source[ :json ].nil?
  end

  def validate_valkey
    # check the signature of the validation key (public key of signkey), using the public key of the current user
    # use the current user public key (derived from the private key) from disk, not from the vault itself!
    # this is the only place to set @validation_key, so it is only available when it is validated
    valkey_digest = OpenSSL::Digest.new( self.cryptoset.valkey_digest )
    
    if @current_user_keyset.verify( valkey_digest, Base64.strict_decode64( self.users.send( @user_info.name.to_sym ).valkey_signature ), self.keysets.valkey )
      @validation_key = OpenSSL::PKey::RSA.new( Base64.strict_decode64( self.keysets.valkey ) )
      return true
    else
      raise "Unable to verify the validation key"
    end
  end
  
  def validate_vaultinfo
    # never validate the vaultinfo without first validating the validation key
    self.validate_valkey
    # check the signature of the vaultinfo 
    vaultinfo_digest = OpenSSL::Digest.new( self.cryptoset.vaultinfo_digest )
    if @validation_key.verify( vaultinfo_digest, Base64.strict_decode64( self.signatures.vaultconfig_signature ), self.except( :signatures, :data  ).digestable( :digest => self.cryptoset.vaultinfo_digest ) )
      return true
    else
      raise "Vault info validation failed"
    end
  end
  
  def validate_data
    # this will also validate the validation key and the vault info itself
    # never read data without validating the vault info 
    self.validate_vaultinfo
    
    # check the signature of the data
    data_digest = OpenSSL::Digest.new( self.cryptoset.data_digest )
    if @validation_key.verify( data_digest, Base64.strict_decode64( self.signatures.data_signature ), self.data.encrypted_data )
      return true
    else
      raise "Data validation failed"
    end
  end

  def sign_data
    # decrypt keysets.signkey, validate vaultinfo first
    self.validate_vaultinfo
    # cannot sign data if current user is not owner
    raise "Must be owner to sign data" if self.users.send( @user_info.name.to_sym ).sign_symkey.nil?
    signkey_cipher = OpenSSL::Cipher.new( self.cryptoset.signkey_cipher )
    signkey_cipher.decrypt
    signkey_cipher.iv = Base64.strict_decode64( self.cryptoset.signkey_init_vector )
    signkey_cipher.key = @current_user_keyset.private_decrypt( Base64.strict_decode64( self.users.send( @user_info.name.to_sym ).sign_symkey ) )
    signkeypair = OpenSSL::PKey::RSA.new( signkey_cipher.update( Base64.strict_decode64( self.keysets.signkey ) ) + signkey_cipher.final )
    
    # sign data
    data_digest = OpenSSL::Digest.new( self.cryptoset.data_digest )
    self.signatures.data_signature = Base64.strict_encode64( signkeypair.sign( data_digest, self.data.encrypted_data ) ) 
  end
  
  def sign_vaultinfo

    raise "Must be owner to sign vaultinfo" if self.users.send( @user_info.name.to_sym ).sign_symkey.nil?
    signkey_cipher = OpenSSL::Cipher.new( self.cryptoset.signkey_cipher )
    signkey_cipher.decrypt
    signkey_cipher.iv = Base64.strict_decode64( self.cryptoset.signkey_init_vector )
    signkey_cipher.key = @current_user_keyset.private_decrypt( Base64.strict_decode64( self.users.send( @user_info.name.to_sym ).sign_symkey ) )
    signkeypair = OpenSSL::PKey::RSA.new( signkey_cipher.update( Base64.strict_decode64( self.keysets.signkey ) ) + signkey_cipher.final )
    
    vaultinfo_digest = OpenSSL::Digest.new( self.cryptoset.vaultinfo_digest )    
    self.signatures.vaultconfig_signature = Base64.strict_encode64( signkeypair.sign( vaultinfo_digest, self.except( :signatures, :data  ).digestable( :digest => self.cryptoset.vaultinfo_digest ) ) )
    
  end
  
  def write_to_disk( options = { :filename => "#{self.name}.vault" } )
    # write the vault to disk
    options[ :filename ] = @original_filename if not @original_filename.nil?
    File.open( options[ :filename ],"wb") do |f|
      f.write(JSON.pretty_generate(self))
    end
  end

end


# todo init vectors belong by their respective data, not in cryptoset
# todo add auto-increasing version number on every vault re-sign, with date and time

class MultiVault < PreVault

  # this loads multivault from a file, or creates a new one with a name
  # it loads the current user key or fails if no key is present
  # action can be: :load => 'file', :create => 'new name'
  # example mv = Multivault.new( :action => { :load => 'somevault' } )  ( or with , :cryptoset => { .... }
  def initialize( options = { :action => {}, :cryptoset => {} } )
    # load current user key if it exists
    current_user_keyfile = File.join( ENV['HOME'], '.multivault', 'user_private_key' )
    current_user_info_file = File.join( ENV['HOME'], '.multivault', 'user_info' )
    if File.exists?( current_user_keyfile )
      @current_user_keyset = OpenSSL::PKey::RSA.new File.read( current_user_keyfile )
      if File.exists?( current_user_info_file )
      then
        @user_info = Hashr.new( JSON.parse( IO.read( current_user_info_file ) ) )
      else
        # an exeption is raised if keyfile exists without user info
        raise "Current user does not have an info file, please create one"
      end
    else
      # cannot proceed without a keyfile
      raise "Current user does not have a keyfile, please create one"
    end    
    # if action is load from file, then do so
    super( :file => options[ :action ][ :load ]  ) if not options[ :action ][ :load ].nil?
    # or create new vault
    begin
      newvault = Hashr.new # PreVault.new( { :name => options[ :action ][ :create ] } )
      # set name
      newvault.name = options[ :action ][ :create ]
      # set cryptoset, merge default into cryptoset options
      if options[ :cryptoset ].nil?
        newvault.cryptoset = DEFAULT_CRYPTOSET
      else
        newvault.cryptoset = DEFAULT_CRYPTOSET.merge( options[ :cryptoset ] )
      end
      # create the current user, will be the only user and owner initialiy
      newvault.users = { @user_info.name.to_sym => { :user_pubkey => Base64.strict_encode64( @current_user_keyset.public_key.to_der ) } }
      
      # create the symmetric key cipher to encrypt the sign key
      signkey_cipher = OpenSSL::Cipher.new( newvault.cryptoset.signkey_cipher )
      signkey_cipher.encrypt
      # store the initialization vector (plain base64)
      newvault.cryptoset.signkey_init_vector = Base64.strict_encode64( signkey_cipher.random_iv )
      # store the symmetric key, but encrypt it with the current user public key, so only the current user can read it
      newvault.users.send( @user_info.name.to_sym ).sign_symkey = Base64.strict_encode64( @current_user_keyset.public_encrypt( signkey_cipher.random_key ) )
      
      # create signkey, public part is validation key, private part will be encypted with signkey_cipher
      signkeypair = OpenSSL::PKey::RSA.new( 4096 )
      # store validation key (public part of signkey) in strict RFC 4648 to avoid problems with signature validation, 
      # use DER format for the same reason (pem is not properly specified)
      newvault.keysets = { :valkey => Base64.strict_encode64( signkeypair.public_key.to_der ) }
      # encrypt private signkey with with sign_symkey and store base64
      newvault.keysets.signkey = Base64.strict_encode64( signkey_cipher.update( signkeypair.to_der ) + signkey_cipher.final )
      
      # create the symmetric key cipher to encrypt the data
      data_cipher = OpenSSL::Cipher.new( newvault.cryptoset.data_cipher )
      data_cipher.encrypt
      # store the initialization vector (plain base64)
      newvault.cryptoset.data_init_vector = Base64.strict_encode64( data_cipher.random_iv )
      # store the symmetric key, but encrypt it with the current user public key, so only the current user can read it
      newvault.users.send( @user_info.name.to_sym ).data_symkey = Base64.strict_encode64( @current_user_keyset.public_encrypt( data_cipher.random_key ) )
      
      # encrypt the data
      newvault.data = { :encrypted_data => Base64.strict_encode64( data_cipher.update( DEFAULT_DATA ) + data_cipher.final ) }
      
      # there are 3 type of signatures, the data signature, the validation key signature (oen for every user) and the vaultconfig signature.
      # the validation key signature and the vaultconfig signature share the same cipher and digest algorithms
      # note that signatures are derived from what is actualy in the vault, the Base64 encoded, encrypted data, not on the data or the encrypted data itself
      
      data_digest = OpenSSL::Digest.new( newvault.cryptoset.data_digest )
      newvault.signatures = { :data_signature => Base64.strict_encode64( signkeypair.sign( data_digest, newvault.data.encrypted_data ) ) }
      
      # use the private key of the current user (owner) to sign the validation key, again on what is actualy in the vault (the base64 encoded validation key)
      valkey_digest = OpenSSL::Digest.new( newvault.cryptoset.valkey_digest )
      newvault.users.send( @user_info.name.to_sym ).valkey_signature = Base64.strict_encode64( @current_user_keyset.sign( valkey_digest, newvault.keysets.valkey ) )
      
      # the signature on the vault itself should be consistent and repeatable, but hashes do not have any inherent order
      # so the digest is based on: a concatenated( sorted list of key + valuedigest concatenated ), again based on the values actualy in the vault.
      # all except the data and signatures themselves are used to create the signature
      # the signature is make with signkey
      vaultinfo_digest = OpenSSL::Digest.new( newvault.cryptoset.vaultinfo_digest )
      newvault.signatures.vaultconfig_signature = Base64.strict_encode64( signkeypair.sign( vaultinfo_digest, newvault.except( :signatures, :data  ).digestable( :digest => newvault.cryptoset.vaultinfo_digest ) ) )
      
      super( newvault )
    end if not options[ :action ][ :create ].nil?
  end
  
  def read_data
    self.validate_data
    data_cipher = OpenSSL::Cipher.new( self.cryptoset.data_cipher )
    data_cipher.decrypt
    data_cipher.iv = Base64.strict_decode64( self.cryptoset.data_init_vector )
    data_cipher.key = @current_user_keyset.private_decrypt( Base64.strict_decode64( self.users.send( @user_info.name.to_sym ).data_symkey ) )
    data_cipher.update( Base64.strict_decode64( self.data.encrypted_data ) ) + data_cipher.final
  end
  
  def write_data( newdata_plain )
    # set and sign
    raise "Must be owner to write data" if self.users.send( @user_info.name.to_sym ).sign_symkey.nil?
    data_cipher = OpenSSL::Cipher.new( self.cryptoset.data_cipher )
    data_cipher.encrypt
    data_cipher.key = @current_user_keyset.private_decrypt( Base64.strict_decode64( self.users.send( @user_info.name.to_sym ).data_symkey ) )
    self.cryptoset.data_init_vector = Base64.strict_encode64( data_cipher.random_iv ) 
    self.sign_vaultinfo # if we move data_init_vector to data we don't have to re-sign the vault itself for write_data
    self.data.encrypted_data = Base64.strict_encode64( data_cipher.update( newdata_plain ) + data_cipher.final )
    self.sign_data
  end
  
  def add_user( request_file, options = { :make_owner => false } )
    
    raise "Must be owner to add user" if self.users.send( @user_info.name.to_sym ).sign_symkey.nil?
    # load request from file
    access_request = PreVault.new( :file => request_file )
    
    # validate vault itself first (will also validate valkey)
    self.validate_vaultinfo
    
    # validate signature on valkey with user pubkey and valkey from vault
    newuser_pubkey = OpenSSL::PKey::RSA.new( Base64.strict_decode64( access_request.user_pubkey ) )
    valkey_digest = OpenSSL::Digest.new( self.cryptoset.valkey_digest )
    raise "Unable to validate valkey signature for new user" if not newuser_pubkey.verify( valkey_digest , Base64.strict_decode64( access_request.valkey_signature ), self.keysets.valkey )
    
    # add user public key, 
    self.users.send( access_request.user_name ) = { :user_pubkey => access_request.user_pubkey :valkey_signature => access_request.valkey_signature }
    
    # give the user a symmetric key for data decryption, encrypted with the newusers' public key
    self.users.send( access_request.user_name ).data_symkey = Base64.strict_encode64( newuser_pubkey.public_encrypt( @current_user_keyset.private_decrypt( Base64.strict_decode64( self.users.send( @user_info.name.to_sym ).data_symkey ) ) ) )
    
    # re-sign vault info
    self.sign_vaultinfo
    
  end
  
  def del_user
  
  end
  
  def make_owner
  
  end
  
  def make_reader
   
  end
  
  def change_vault_name
  
  end
  
  def current_user_name
    # returns current user name (for MVaultHelper )
    @user_info.name
  end
  
  def current_user_pubkey
    # returns current user pubkey in base64 (for MVaultHelper )
    Base64.strict_encode64( @current_user_keyset.public_key.to_der )
  end
  
  def current_user_key
    # returns current user keypair (for MVaultHelper)
    @current_user_keyset
  end
  

    # todo: create files section to encrypt/decrypt external files
    # assuming io is the IO representing your uploaded file 
    # and out is the IO you are writing to
    # while chunk = io.read(1024)
    #   out << cipher.update(chunk)
    # end
    # out << cipher.final
   
  

end

class MVaultHelper < PreVault
  
  def create_key( username )
    # create key and write it if it doesn't exist
    keyfile = File.join( ENV['HOME'], '.multivault', 'user_private_key' )
    raise "Keyfile already exists, please use delete_key first" if File.exists?( keyfile )
    new_keyset = OpenSSL::PKey::RSA.new( 4096 )
    FileUtils.mkdir_p File.dirname keyfile
    open( keyfile, 'w' ) { |io| io.write( new_keyset.to_pem ) }
    # write user info
    userfile = File.join( ENV['HOME'], '.multivault', 'user_info' )
    open( userfile, 'w' ) { |io| io.write( JSON.pretty_generate( { :name => username } ) ) }
    FileUtils.chmod( "u=r,og-rwx", keyfile )
    FileUtils.chmod( "u=r,og-rwx", userfile )
    FileUtils.chmod( "u=rx,og-rwx", File.dirname( keyfile ) )
  end
  
  def delete_key
    keyfile = File.join( ENV['HOME'], '.multivault', 'user_private_key' )
    userfile = File.join( ENV['HOME'], '.multivault', 'user_info' )
    raise "Keyfile doesn't exists, cannot delete something which isn't there" if not File.exists?( keyfile )
    FileUtils.chmod( "u=rwx", File.dirname( keyfile ) )
    FileUtils.chmod( "u=rw", keyfile )
    FileUtils.chmod( "u=rw", userfile )
    File.delete( keyfile )
    File.delete( userfile )
    Dir.rmdir( File.dirname( keyfile ) )
  end
  
  def request_access( vault_file, request_file )
    # creates a json file with the users' public key and a personal signature on the validation key
    # the owner who adds the user should trust or validate the origin and content of the access request
    vault = MultiVault.new( :action => { :load => vault_file } )
    access_request = PreVault.new( { :user_name => vault.current_user_name, :user_pubkey => vault.current_user_pubkey, :access_to => vault.name } )
    
    # use the private key of the current user (owner) to sign the validation key
    valkey_digest = OpenSSL::Digest.new( vault.cryptoset.valkey_digest )
    access_request.valkey_signature = Base64.strict_encode64( vault.current_user_key.sign( valkey_digest, vault.keysets.valkey ) )
    
    access_request.write_to_disk( :filename => request_file )
    
  end
  
end

MVAULT = MVaultHelper.new
