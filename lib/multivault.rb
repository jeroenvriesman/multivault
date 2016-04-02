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

# this loads data into hashr, either from a file or from json data
class Hashr_loader < Hashr
  def initialize( source = {} )
    super( JSON.parse( IO.read( source[ :file ] ) ) ) if not source[ :file ].nil?
    super( JSON.parse( source[ :json ] ) ) if not source[ :json ].nil?
    super( source ) if source[ :file ].nil? and source[ :json ].nil?
  end
end

class MultiVault < Hashr_loader

  # this loads multivault from a file, or creates a new one with a name
  # it loads the current user key or fails if no key is present
  # action can be: :load => 'file', :create => 'new name'
  # :create_keys => 'username'? create keys op basis van global constant object
  def initialize( action = {} )
    super( :file => action[ :load ]  ) if not action[ :load ].nil?
    begin
      newvault = Hashr.new
      newvault.name = action[ :create ]
      
      super( newvault )
    end if not action[ :create ].nil?
  end
  
  
  # will read or create the private key for the current user (no passwd)
  def current_user_keyset
    # use File.join for linux/windows compatibility
    keyfile = File.join( ENV['HOME'], '.multivault', 'user_private_key' )
    # create if not exists
    if File.exists? keyfile 
      @current_user_keyset = OpenSSL::PKey::RSA.new File.read keyfile
    else
      @current_user_keyset = OpenSSL::PKey::RSA.new 4096
      FileUtils.mkdir_p File.dirname keyfile
      open keyfile, 'w' do |io| io.write @current_user_keyset.to_pem end
      FileUtils.chmod "u=r,og-rwx", keyfile
      FileUtils.chmod "u=rx,og-rwx", File.dirname( keyfile )
    end
  end
  
  def create( plain_data, options = { :data_cipher => 'aes-128-cbc', :signature_digest => 'sha256', :sign_key_cipher => 'aes-128-cbc' } )
    # create will make the following parts of the vault:
    # for create the assumption is that current_user will be the owner, and initialy the only user
    # 1) config,json, a json with the settings, this is the @config (as an array, but will be json on disk), and json pp for signing
    # 2) a symmetric key, encrypted with current_user_public_key (not stored, method of the private key)
    # 3) data, encrypted with the SYMKEY
    # 4) a "signkey", encrypted with a random symmetric key sign_key_symkey 
    # 5) sign_key_symkey encrypted with current_user_public_key
    # 6) the "validation key", which is the public key of the signkey
    # 7) a signature on the validation key (owner-bound)
    # 8) the "master" signature, a signature on everything exept the signature itself.
    # n.b: a new user needs the validation key to create an add-me request, a user needs the validation key and checks his own signature on the validation key
    # an owner has access to the private "signkey", but the owner would still like to validate (prevent tampering with signkey), so owner also needs a signature on 
    # the validation key
    
    # assuming io is the IO representing your uploaded file 
    # and out is the IO you are writing to
    # while chunk = io.read(1024)
    #   out << cipher.update(chunk)
    # end
    # out << cipher.final
    
    # do not use ecb mode, todo: check for ecb mode request
    
    # create the config array
    @config[ :data_cipher ] = options[ :data_cipher ]
    @config[ :sign_key_cipher ] = options[ :sign_key_cipher ]
    @config[ :name ] = @name
    @config[ :signature_digest ] = options[ :signature_digest ]
    
    # initialize the cipher and create symmetric key encrypted with the owners public key
    data_cipher = OpenSSL::Cipher.new( @config[ :data_cipher ] )
    data_cipher.encrypt
    @symkey = @current_user_keyset.public_encrypt data_cipher.random_key # only owner/creator has the private key to read this 
    
    # create an encrypted version of the data, store the initialization vector
    @config[ :data_initialization_vector ] = data_cipher.random_iv # init vector
    @data_encrypted = data_cipher.update( plain_data ) + data_cipher.final
    
    # create the sign key and encrypt with symmetric key, the corresponding symmetric key is encypted with owner public key
    
    
    
  end
  
  private :current_user_keyset

end
