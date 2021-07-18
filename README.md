# Cloud-Storage-Scheme-POC
Implementation of the proposed scheme from my dissertation thesis.

The proposed solution will use identity-based encryption (Cocks IBE) in order to force the provider 
to notify the user when a file is accessed and to provide the option of file-sharing (and to avoid using ACLs).
This effect will be obtained using cryptographic methods. A log-based implementation can also be viable, 
although depending on approach, this variant could be prone to entities faking logs or other similar issues.
The log in process will be zero-knowledge using the Fiat-Shamir Identification Scheme. This will deter the 
provider from attempting to reverse hash functions to gain the password, which in turn also grants it
unlimited access to the data. For the average customer this is not a problem as the perks gained are likely 
not worth the effort. For high-profile customers with sensitive information this can be very important.
The keys will be stored in the cloud and the encryption and decryption operations will be performed 
locally. This approach discourages the client from breaking the terms of services because they will be 
inspected regularly. The user will also have the ability to tell whether the file has been viewed or not. On 
the other hand, the provider is able to access the files at all times, but he cannot do it covertly. Ideally, the 
terms of service would state a certain weekly/monthly/yearly inspection interval or a semi-fixed number of 
inspections over a time period, so that if the provider wishes to break the rule, the user can contest its 
decision and act accordingly (this can range anywhere from taking legal action to simply migrating to 
another provider). All of this means that the provider can still use the client information to create certain 
profiles with the purpose of manipulation, performance analysis and personalizing advertisements. As 
mentioned above this will always be the case in such a scenario (where the provider has access to the data). 
However, the approach chosen will inconvenience and even slow down such entities as they will not be 
able to constantly learn. If the provider wishes permanent access to a file, he will have to create a copy
locally, which comes with additional concerns and costs.
Most of the cloud components are considered to be trusted but curious. The main downside of 
identity-based encryption is that the module that generates the keys also has access to them, meaning the 
entity managing this module would be able to decrypt all the files stored, on top of being able to perform 
other operations that can break the terms of service (such as changing the keys to deny the owners access 
to the files). Therefore, the key managing module and the file managing module must be trusted fully.

More details at 45 in the PDF.
