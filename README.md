# Cloud-Storage-Scheme-POC
Implementation of the proposed scheme from my dissertation thesis.

The proposed solution will use identity-based encryption (Cocks IBE) in order to force the provider 
to notify the user when a file is accessed and to provide the option of file-sharing (and to avoid using ACLs).
This effect will be obtained using cryptographic methods. A log-based implementation can also be viable, 
although depending on approach, this variant could be prone to entities faking logs or other similar issues.
The log in process will be zero-knowledge using the Fiat-Shamir Identification Scheme. This will deter the 
provider from attempting to reverse hash functions to gain the password, which in turn also grants it
unlimited access to the data. For the average customer this is not a problem as the perks gained are likely 
not worth the effort. 

More details at 45 in the PDF.
