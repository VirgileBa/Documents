//---------Bartolo Virgile M2 crypto--------------
import java.math.BigInteger;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.io.IOException;

public class rsa{
	
	
	/**reads a file encoded in said standard**/
	public static String readFile(String file){
		try{
			byte[] inputbytes = Files.readAllBytes(Paths.get(file));
			String s = new String(inputbytes, "ISO-8859-1");
			return s;
			}
		catch(IOException e){
			System.out.println("error at reading file");
			System.out.println(e);
			return "";
			}
		}
		
	
	/**transform a string into a biginteger**/
	public static BigInteger OS2IP(String s){
		BigInteger result = new BigInteger("0");
		int len = s.length();
		BigInteger fact = new BigInteger("1");
		BigInteger big256 = new BigInteger("256");
		for(int i=len-1; i>=0; i--){	/**goes from right to left**/	
			//System.out.printf("code point:%d\n", s.codePointAt(i) );	/**prints the values**/
			result = result.add(
			BigInteger.valueOf( s.codePointAt(i) ).multiply(fact)
			);
			fact = fact.multiply(big256);
			}
		return result;
		}	


	/**transform a biginteger into a String**/
	public static String I2OSP(BigInteger i){
		BigInteger big256 = new BigInteger("256");
		BigInteger big0 = new BigInteger("0");		
		String result="";
		BigInteger[] tab = i.divideAndRemainder(big256);
		i = tab[0];
		result += (char) tab[1].intValue();
		while( !i.equals(big0) ){ /**while the quotient is >0, we take the rest and we go on with the calculation on i/256 **/
			tab = i.divideAndRemainder(big256);       
			i = tab[0];
			result = (char) tab[1].intValue()+result; /**we add the character to the string**/
			}
		return result;		
		}
	
	/**transform a biginteger into a String, overloading version with the argument l**/
	public static String I2OSP(BigInteger i, int l){
		BigInteger big0 = new BigInteger("0");		
		BigInteger big256 = new BigInteger("256");
		String result="";
		BigInteger[] tab = i.divideAndRemainder(big256);
		i = tab[0];
		result += (char) tab[1].intValue();
		l-=1;
		while(!i.equals(big0)){		/**the while and then the for means it will always at least output the initial char, at most, the chars with the 0's in front**/
			tab = i.divideAndRemainder(big256);       
			i = tab[0];
			result = (char) tab[1].intValue() + result ; 
			l-=1;
			}
			
		for(int j=0;j<l;j++){		/**adding the 0's**/
			result = (char) 0 + result;
			}	
		return result;					
		}
	
	
	/**this method splits the string in equal parts and what's left is put in the last string of the array**/
	public static String[] equalSplit(String s, int n){
		int len = s.length()/n;
		if(n>s.length() || s.length()%n!=0){len+=1;}	/**the size is how much strings of length n fits plus one if n>s (then the array is of size 0)**/
														/**or if there's a part left out**/			
		String[] res = new String[len];					
		for(int i=0;i<len-1;i++){
			res[i]= s.substring(i*n,(i+1)*n);
			}
		res[len-1]= s.substring(n*(len-1)); 			/**adding what's left**/
		return res;
		}
	
	/**cipher**/
	public static String rsaChiff(String s,BigInteger n,BigInteger e){
		BigInteger big256 = new BigInteger("256");
		BigInteger fact = new BigInteger("1");

		/**calculating the size, while 2^size<n, size +=1**/
		int size = 0;
		while(n.compareTo(fact)!=-1){
			fact = fact.multiply(big256);
			size+=1;
			}		
			
		String[] tabstr = equalSplit(s, size-1);
		BigInteger m;
		String res = ""; 
		
		for(int i =0;i<tabstr.length;i++){
			m = OS2IP(tabstr[i]).modPow(e,n);		/**needed calculations**/
			//System.out.printf("liste entier: %d ||chiffré: %d \n",OS2IP(tabstr[i]),m); 	/**prints the value of the m and the m prime**/
			
			res += I2OSP(m,size);					/**adding the calculated string**/
			}
		return res;
		}
	
	
	/**decipher, roughmy the same as the cipher**/
	public static String rsaDechiff(String s,BigInteger n,BigInteger d){
		BigInteger big256 = new BigInteger("256");
		BigInteger fact = new BigInteger("1");

		int size = 0;
		while(n.compareTo(fact)!=-1){
			fact = fact.multiply(big256);
			size+=1;
			}		
		String[] tabstr = equalSplit(s, size);
		BigInteger m;
		String res = ""; 			
		for(int i =0;i<tabstr.length-1;i++){
			m = OS2IP(tabstr[i]).modPow(d,n);
			res += I2OSP(m,size-1); /**size-1 to not get unwanted " " in the text**/
			}
		m = OS2IP(tabstr[tabstr.length-1]).modPow(d,n);
		res += I2OSP(m);	
		return res;
		}	
	
	
	
	public static void main(String[] args){
		
BigInteger p = new BigInteger("15692520342819582761");
BigInteger q = new BigInteger("17768212656255259967");
BigInteger n = new BigInteger("278828038563830041363494578598526628887");
BigInteger e = new BigInteger("3");
BigInteger pq = ( p.subtract(new BigInteger("1")) ).multiply(q.subtract(new BigInteger("1")));
BigInteger d = e.modInverse(pq);		
		
		//BigInteger n = new BigInteger("6912193");
		//BigInteger e = new BigInteger("3");
		//System.out.println("ca compile");
		//String s= "bonjour";
		//System.out.println(I2OSP(OS2IP("abc"),4));
		System.out.println( rsaDechiff(readFile("secret"),n,d) );
		
		}


}
