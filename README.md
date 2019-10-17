# Interview Tips (Information Security)
This page is a summary of interviews I have been through, covered a decent breadth of roles, got multiple rejects however, learned from each interview, collected constructive feedbacks and went ahead.
Hope these questions/ tips could help you.

Roles which it generally covers are as follows:
- Cybersecurity Intern
- Penetration Testing Intern/ Red Team
- Web App/ Application Security Intern 
- Product Security Intern
- Infrastructure Security Intern

Quick tip:
- Review your resume and ask questions related to it to yourself beforehand
- If you are not aware of any question/concept, don't run around the topic, convey that you could learn it given an environment to work on  
   *You cannot know everything, be humble to accept if you answered something wrong or in need for clarification*
- Prepare a short bio about yourself beforehand to introduce yourself  
- Be sure about your end goal and why infosec?
- Lastly, do ask about feedback at the end of the interview, *why, because:* it helps in knowing and filling the gaps of your current knowledge in infosec

I have tried to jot down all the possible question below which I came across and provided answers for few.
Rest you could google for their specific answers and if you want to dive deep. Apart from that, there are few references in the end do have a look. Those were really helpful.

*Would love to add more question as I move ahead and check my notes, however would appreciate if you could give me a constructive feedback about this by contacting me via jiger13@gmail.com.
If you came across something, which is not covered out here please feel free to share.*

## Common questions

1. Security Triads:

What is CIA?
- Confidentiality
- Integrity
- Availability

What is AAA?
- Authentication
- Authorization
- Accounting

2. Difference between Threat, Vulnerability, Exploits and Risk and how those are related to Assets
- Threat:  
A threat is what we’re trying to protect against
- Vulerability:  
A vulnerability is a weakness or gap in our protection efforts
- Exploit:  
An ability/program (may be a software or social engineering skill) that has been developed to attack an asset by taking advantage of a vulnerability  
- Risk:  
Risk is the intersection of assets, threats, and vulnerabilities
- Asset:  
An asset is what we’re trying to protect

3. What is IAM and why it is been used?   
   IAM is Identity Access Management which used to segreagate roles and responsibilities within an organization. It is a critical piece in security. It help in maintaining Access level security and privileges

## Security in general

### Phases of Network Intrusion Attack:
- Reconnaissance/ Information Gathering
- Gaining the needed access
- Maintaining the access
- Covering the tracks (Deleting logs, backdoors and hiding all controls)

## Web Application Security

1. Common Question:
- OWASP Top 10
- What is XSS (Cross-site Scripting)
- How to combat XSS: *Briefly use appropriate input validation*
  - Look for CSP (Content-Security-Policy) Header
- Different types of XSS: 
   *Reflected, Stored and DOM-based*
- What are sources and sinks in DOM which could lead to XSS:  
https://www.netsparker.com/blog/web-security/dom-based-cross-site-scripting-vulnerability/
- What is CSRF 
   *This is the sweetest question which every other interviewer would love to ask*  
   *Quick Tip:* Be brief, if asked then only explain the whole story   
   
   Cross-Site Request Forgery (CSRF) is an attack that forces an end user to execute unwanted actions on a web application in which they're currently authenticated. CSRF attacks specifically target **state-changing requests, not theft of data**, since the attacker has no way to see the response to the forged request. With a little help of social engineering (such as sending a link via email or chat), an attacker may trick the users of a web application into executing actions of the attacker's choosing. If the victim is a normal user, a successful CSRF attack can force the user to perform state changing requests like transferring funds, changing their email address, and so forth. If the victim is an administrative account, CSRF can compromise the entire web application.
   
- How to combat CSRF:  
   Use Anti-CSRF Tokens  
   Use same-origin policy  
   Usage of Referrer header
- What is HTML/ URL Encoding
- Is HTTP protocol stateless?  
   HTTP is inherently stateless protocol however server uses cookies to make it stateless
- What are types of Injections: *SQL, Command, OS*
- How to combat SQL injections  
   Use paramterized queries and stored procedures

2. Check for headers which helps in providing security (Check the Urls and go throught the content, it would help in building your fundamentals):   
- CSP (Content-Security Policy) [https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy]
- CORS (Cross-Origin Resource Sharing) [https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS]
- Same-Origin policy [https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy]

3. There would be rare scenarios when an interviewer would ask these, I came across the followings in later stages of few interviews, thought of mentioning:

- What is XXE (XML External Entities)?
  XML external entity injection (also known as XXE) is a web security vulnerability that allows an attacker to interfere with an application's processing of XML data. It often allows an attacker to view files on the application server filesystem, and to interact with any backend or external systems that the application itself can access.
    Check this out [https://portswigger.net/web-security/xxe]
    E.g: 
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
    <stockCheck><productId>&xxe;</productId></stockCheck>

In some situations, an attacker can escalate an XXE attack to compromise the underlying server or other backend infrastructure, by leveraging the XXE vulnerability to perform server-side request forgery (SSRF) attacks.
- What is SSRF (Server Side Request forgery)  
  Could be used to pivot into the internal network
- How to secure 3-tier web architecture
- What is Kerberos
  https://www.varonis.com/blog/kerberos-authentication-explained/
- What is Secret Management and Vaults
  https://www.hashicorp.com/resources/introduction-vault-whiteboard-armon-dadgar

## Network Security
- Difference between Symmetric and Asymmetric cryptography
- Difference between Public key cryptography and Asymmtric key cryptography: Both are same *Tricky Question*
- Modes in Cryptography (Eg. EBC, CBC, etc)
- Cipher suite insight:  
  Ex: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256  
  https://scotthelme.co.uk/https-cheat-sheet/  
- During Data Compression and Encrytion what happens first compression or encryption  
  Compression happens first, since the entropy (spread) of randomness in data is low, thus higher compression could be achievable, thus it is advantageous to first compress then encrypt.
- Difference between Encryption, Encoding, Hashing and Obfuscation  
https://danielmiessler.com/study/encoding-encryption-hashing-obfuscation/ 
 - What is Rainbow-table: *Briefly it is a collection of precomputed hashes*
 - How TLS works?  
 *This is an amazing image I stumbled upon, it helped me to understand TLS in layman language*  
 http://i.imgur.com/5T2fJsG.png
 - What is Certificate Signing
 - How Traceroute works
 - How Nmap works
 - What is Certification Authority (CA)
 - What is DMZ and what are the components involved in it
 - What port does ping work over?  
  *A trick question* to be sure, but an important one.   
  Hint: ICMP is a layer 3 protocol (it doesn’t work over a port) A good variation of this question is to ask whether ping uses TCP or UDP. An answer of either is a fail, as those are layer 4 protocols.

## Cloud Security
Would talk in general in terms of AWS, however there are other cloud providers such as Azure, GCP, Digital Ocean, etc..
- General components of AWS:  
   S3, EC2, Buckets, IAM, Cloud trial, Cloud watch
- What is IAM and their components: To be brief IAM is used for Access Management where it used Roles (for temporary access), Policies, Groups and Users for its functioning
- What is EC2: It is an Elastic instance for spinning up a Virtual Machine
- Does EC2 has encrytion: Yes, it does. Amazon EBS encryption offers a simple encryption solution for your EBS volumes without the need to build, maintain, and secure your own key management infrastructure. Amazon EBS encryption uses AWS Key Management Service (AWS KMS) customer master keys (CMKs) when creating encrypted volumes and any snapshots created from them.
More could be found ... below
https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html

## Binary Exploitation

- Tools could be used for debugging a binary:  
   Linux: gdb, radare, clutter (GUI for radare)  
   Windows: IDA, Binary Ninja
- What is Buffer Overflow
- What is Format String Vulnerability
- Difference between Stack and Heap region (Might consider looking into Code, Text and Bss region as well)
- What are Stack Cookies
- What is ASLR and why it is used?
- What is non-executable memory?


## References
Learning Resource:
https://portswigger.net/web-security/
OWASP Top 10:  
https://www.owasp.org/images/7/72/OWASP_Top_10-2017_%28en%29.pdf.pdf  
Infosec Interview Questions:  
https://danielmiessler.com/study/infosec_interview_questions  
Top Pentest Questions:  
https://resources.infosecinstitute.com/top-30-penetration-tester-pentester-interview-questions-and-answers-for-2019/#gref  
Python tips:  
https://www.codementor.io/sheena/essential-python-interview-questions-du107ozr6  
AWS User Guide:  
https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/concepts.html  
SMB and Samba insight:
https://fitzcarraldoblog.wordpress.com/2016/10/17/a-correct-method-of-configuring-samba-for-browsing-smb-shares-in-a-home-network/
