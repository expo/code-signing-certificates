#!/usr/bin/env node

import { v4 as uuidv4 } from 'uuid';

export async function run(): Promise<void> {
  // Output the resulted OID with best practice info
  const oidText = `
Your root OID is: ${generateOID()}
This prefix should be used to name your schema attributes and classes. For example: if your prefix is "Microsoft", you should name schema elements like "microsoft-Employee-ShoeSize".
For more information on the prefix, view the Schema Naming Rules in the server Application Specification (http://www.microsoft.com/windowsserver2003/partners/isvs/appspec.mspx).
You can create subsequent OIDs for new schema classes and attributes by appending a .X to the OID where X may be any number that you choose.  A common schema extension scheme generally uses the following structure:
If your assigned OID was: 1.2.840.113556.1.8000.2554.999999 then classes could be under: 1.2.840.113556.1.8000.2554.999999.1 which makes the first class OID: 1.2.840.113556.1.8000.2554.999999.1.1 the second class OID: 1.2.840.113556.1.8000.2554.999999.1.2     etc...
Using this example attributes could be under: 1.2.840.113556.1.8000.2554.999999.2 which makes the first attribute OID: 1.2.840.113556.1.8000.2554.999999.2.1 the second attribute OID: 1.2.840.113556.1.8000.2554.999999.2.2     etc...
Here are some other useful links regarding AD schema:
Understanding AD Schema http://technet2.microsoft.com/WindowsServer/en/Library/b7b5b74f-e6df-42f6-a928-e52979a512011033.mspx
Developer documentation on AD Schema: http://msdn2.microsoft.com/en-us/library/ms675085.aspx
Extending the Schema http://msdn2.microsoft.com/en-us/library/ms676900.aspx
Step-by-Step Guide to Using Active Directory Schema and Display Specifiers http://www.microsoft.com/technet/prodtechnol/windows2000serv/technologies/activedirectory/howto/adschema.mspx
Troubleshooting AD Schema http://technet2.microsoft.com/WindowsServer/en/Library/6008f7bf-80de-4fc0-ae3e-51eda0d7ab651033.mspx
`;
  console.log(oidText);
}

function generateOID(): string {
  const guidString = uuidv4();

  // The Microsoft OID Prefix used for the automated OID Generator
  const oidPrefix = '1.2.840.113556.1.8000.2554';

  // Split GUID into 7 hexadecimal numbers
  const guidPart0 = guidString.substring(2, 2 + 4).trim();
  const guidPart1 = guidString.substring(6, 6 + 4).trim();
  const guidPart2 = guidString.substring(11, 11 + 4).trim();
  const guidPart3 = guidString.substring(16, 16 + 4).trim();
  const guidPart4 = guidString.substring(21, 21 + 4).trim();
  const guidPart5 = guidString.substring(26, 26 + 6).trim();
  const guidPart6 = guidString.substring(32, 32 + 6).trim();

  // Convert the hexadecimal to decimal
  const oidPart0 = parseInt(guidPart0, 16);
  const oidPart1 = parseInt(guidPart1, 16);
  const oidPart2 = parseInt(guidPart2, 16);
  const oidPart3 = parseInt(guidPart3, 16);
  const oidPart4 = parseInt(guidPart4, 16);
  const oidPart5 = parseInt(guidPart5, 16);
  const oidPart6 = parseInt(guidPart6, 16);

  // Concatenate all the generated OIDs together with the assigned Microsoft prefix and return
  return (
    oidPrefix +
    '.' +
    oidPart0 +
    '.' +
    oidPart1 +
    '.' +
    oidPart2 +
    '.' +
    oidPart3 +
    '.' +
    oidPart4 +
    '.' +
    oidPart5 +
    '.' +
    oidPart6
  );
}

run();
