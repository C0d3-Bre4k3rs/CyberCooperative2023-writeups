# CRYPTO: Eve and The Thousand Keys
solvers: [N04M1st3r](https://github.com/N04M1st3r), [L3d](https://github.com/imL3d)  
writeup-writer: [L3d](https://github.com/imL3d)  
**Description:**
> We've found an exposed SSH service on the target company network. We scraped the SSH public keys from all the developers from their open source profiles but public keys are kind of useless for this. Can you get us in?
> ssh challenge@0.cloud.chals.io -p 17009

**files (copy):** [public.zip](files/public.zip)  

In this challenge we received 1000 public SSH keys that we need to use in order to connect to the target machine.
## Solution
Right off the bat, when examining this question it seems _impossible_, especially in the given timeframe - we don't know which public keys are still valid in the eyes of the server and furthermore, we don't have the correspondent private keys that we need in order to authenticate!  
But now we have broken down this problem into two major steps:
1. Identify the valid public RSA keys.
2. Reconstruct the private RSA keys for the public keys we found.   

In order to solve the first step, we use an important part of the way SSH works - before sending the private key to authenticate, the client (us in this case) needs to demonstrate that it has the private key corresponding to a public key that is authorized on the server, and thus we in order to make sure that it's private key is okay, it sends the public key to the server ([Further Read](https://security.stackexchange.com/questions/152594/understanding-the-offering-rsa-public-key-step-during-ssh-connection-initializ)).  
Using this step, we can only send the public keys and check which one the server accepts!
Quickly constructing this code, to scan try and use all the files and find which one is working (will throw an error):
```bash
#!/bin/bash

for FILE in $(ls public)
do
        echo $FILE
        ssh challenge@0.cloud.chals.io -p 17009 -i public/$FILE -o BatchMode=yes -o StrictHostKeyChecking=no
        # Try and connect to the machine without prompting us to the password
done
```
We get only one unique result of this is for key  `854` (it couldn't parse it as a private key, of course).  
 Step 1 is complete! Now we just need to get reconstruct the private key and we solved the challenge!  
  
 For this step we need to get our hands dirty with the inner working of the RSA keys.   
 From the public key we need to get the exponent (`e`) and the modulo (`n`, product of two large prime numbers). This can be easily done since this is stored on the public key:
 ```python
def extract_rsa_components(public_key_text):
    # Load the public key
    public_key = serialization.load_ssh_public_key(
        public_key_text.encode('utf-8'),
        backend=default_backend()
    )

    # Extract N and e from the public key
    N = public_key.public_numbers().n
    e = public_key.public_numbers().e

    return N, e
 ```
After that comes the hard part - we need to get the prime factors that construct `N`- `p` and `q`.  
For this we can use any factorization program (ex: `primefac`), and we just have to hope these are [weak primes](https://en.wikipedia.org/wiki/Strong_prime)..   
BINGO! we found `p` and `q` :).  
Using our newly found knowledge we can construct the _private RSA key_:
```python
from Crypto.Util.number import inverse
from Crypto.PublicKey import RSA

p  =  30861_299616_118517_364960_406815_911055_976243_110157_683723_319442_022873_349805_419532_151757_039189_854767_848548_715555_865687_768882_574244_301553_049602_003559_100636_144903_896877_173789_553598_765259_403720_551124_697870_578287_287262_101929_970140_879662_863582_135843_358217_467942_231087_553356_176050_156208_156525_711112_211997_263141_509728_630639_228901_822847_186260_694710_469056_713124_099983_925425_183538_773140_902560_773853_220066_101946_250791_679802_294219_974455_544074_264409_998357_403679_214832_515768_482336_566193_088628_924203_936027_207609_854925_079137_622222_790588_341307_879490_778229_706710_050341_839987_087470_733731_205351_304558_418796_553185_016142_376769_459733_857564_487527
q  =  30861_299616_118517_364960_406815_911055_976243_110157_683723_319442_022873_349805_419532_151757_039189_854767_848548_715555_865687_768882_574244_301553_049602_003559_100636_144903_896877_173789_553598_765259_403720_551124_697870_578287_287262_101929_970140_879662_863582_135843_358217_467942_231087_553356_176050_156208_156525_711112_211997_263141_509728_630639_228901_822847_186260_694710_469056_713124_099983_925425_183538_773140_902560_773853_220066_101946_250791_679802_294219_974455_544074_264409_998357_403679_214832_515768_482336_566193_088628_924203_936027_207609_854925_079137_622222_790588_341307_879490_778229_706710_050341_839987_087470_733731_205351_304558_418796_553185_016142_376769_459733_857564_489057
N  =  952_419813_995836_947275_497915_811956_467244_873205_741510_752896_284035_314516_961739_679178_389693_778475_589695_117585_714904_018177_262141_939242_553848_717016_738701_193627_687579_521562_942892_529305_886395_450474_932710_088165_653853_573541_423903_825238_859633_051272_624257_763712_501795_538764_924058_575819_125749_832903_797895_218009_087685_147449_103151_872561_760345_651418_181162_698899_642092_409478_972988_923250_588900_640764_775330_242974_742049_126979_359141_500912_010940_902199_691552_097606_346988_592773_480778_604969_241348_737658_545197_044078_207578_215236_325880_048570_005698_902151_429681_738214_882907_076930_579854_871136_781308_235712_152932_281441_682193_300190_605834_194733_306012_347602_106783_778522_374410_138013_579552_220695_209495_922305_403459_241560_590013_776624_848008_178680_512295_080648_678693_582250_079291_305944_285720_547730_709602_412666_295581_860165_423635_285892_574190_567667_254940_521202_137352_530558_148128_828200_595066_102187_154831_079723_828239_299147_225649_933271_723464_971702_849899_341596_100283_328423_968424_257513_376485_094862_650220_806148_003910_152608_322946_875062_589536_883910_291665_237184_170718_718649_446339_273245_032170_921852_277454_427644_318175_432552_065601_558775_385138_833520_330849_738734_334134_361153_824649_984248_398192_693906_734178_959368_337043_068436_362753_410330_180723_156553_139936_369421_374896_668097_702304_743651_519804_492039
e  =  65537

phi  = (p-1)*(q-1)
d  = inverse(e, phi)

key  = RSA.construct( (N,e,d) )
private_key_path  =  "private_key.pem"
with  open(private_key_path, "wb") as  private_key_file:
	private_key_file.write(key.export_key())
```
all we have to do left is:  
```bash
 $ ssh challenge@0.cloud.chals.io -p 17009 -i .\private_key.pem
flag{guess_it_wasnt_prime_season}
```  
