import { v4 as uuidv4 } from 'uuid';

export async function run(): Promise<void> {
  // Output the resulted OID with best practice info
  const VBCRLF = '\n';
  const VBCR = '\n';
  const oidText =
    'Your root OID is: ' +
    VBCRLF +
    generateOID() +
    VBCRLF +
    VBCRLF +
    VBCRLF +
    'This prefix should be used to name your schema attributes and classes. For example: ' +
    'if your prefix is "Microsoft", you should name schema elements like "microsoft-Employee-ShoeSize". ' +
    'For more information on the prefix, view the Schema Naming Rules in the server ' +
    'Application Specification (http://www.microsoft.com/windowsserver2003/partners/isvs/appspec.mspx).' +
    VBCRLF +
    VBCRLF +
    'You can create subsequent OIDs for new schema classes and attributes by appending a .X to the OID where X may ' +
    'be any number that you choose.  A common schema extension scheme generally uses the following structure:' +
    VBCRLF +
    'If your assigned OID was: 1.2.840.113556.1.8000.2554.999999' +
    VBCRLF +
    VBCRLF +
    'then classes could be under: 1.2.840.113556.1.8000.2554.999999.1 ' +
    VBCRLF +
    'which makes the first class OID: 1.2.840.113556.1.8000.2554.999999.1.1' +
    VBCRLF +
    'the second class OID: 1.2.840.113556.1.8000.2554.999999.1.2     etc...' +
    VBCRLF +
    VBCRLF +
    'Using this example attributes could be under: 1.2.840.113556.1.8000.2554.999999.2 ' +
    VBCRLF +
    'which makes the first attribute OID: 1.2.840.113556.1.8000.2554.999999.2.1 ' +
    VBCRLF +
    'the second attribute OID: 1.2.840.113556.1.8000.2554.999999.2.2     etc...' +
    VBCRLF +
    VBCRLF +
    'Here are some other useful links regarding AD schema:' +
    VBCRLF +
    'Understanding AD Schema' +
    VBCRLF +
    'http://technet2.microsoft.com/WindowsServer/en/Library/b7b5b74f-e6df-42f6-a928-e52979a512011033.mspx ' +
    VBCRLF +
    VBCRLF +
    'Developer documentation on AD Schema:' +
    VBCRLF +
    'http://msdn2.microsoft.com/en-us/library/ms675085.aspx ' +
    VBCRLF +
    VBCRLF +
    'Extending the Schema' +
    VBCRLF +
    'http://msdn2.microsoft.com/en-us/library/ms676900.aspx ' +
    VBCRLF +
    VBCRLF +
    'Step-by-Step Guide to Using Active Directory Schema and Display Specifiers ' +
    VBCRLF +
    'http://www.microsoft.com/technet/prodtechnol/windows2000serv/technologies/activedirectory/howto/adschema.mspx ' +
    VBCRLF +
    VBCRLF +
    'Troubleshooting AD Schema ' +
    VBCR +
    'http://technet2.microsoft.com/WindowsServer/en/Library/6008f7bf-80de-4fc0-ae3e-51eda0d7ab651033.mspx  ' +
    VBCRLF +
    VBCRLF;

  console.log(oidText);
}

function generateOID(): string {
  const guidString = uuidv4();

  // The Microsoft OID Prefix used for the automated OID Generator
  const oidPrefix = '1.2.840.113556.1.8000.2554';

  // Split GUID into 6 hexadecimal numbers
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
