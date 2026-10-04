const fs = require('fs');
const path = require('path');

const REGISTRY_PATH = path.join(__dirname, '../data/government-registry.json');

function loadRegistry() {
  try {
    if (fs.existsSync(REGISTRY_PATH)) {
      const data = JSON.parse(fs.readFileSync(REGISTRY_PATH, 'utf8'));
      return {
        aadhaar: data.aadhaar || [],
        passports: data.passports || [],
        pan: data.pan || []
      };
    }
  } catch (err) {
    console.error('Error reading government registry:', err);
  }
  return { aadhaar: [], passports: [], pan: [] };
}

function saveRegistry(data) {
  fs.writeFileSync(REGISTRY_PATH, JSON.stringify(data, null, 2), 'utf8');
}

function normalizeName(str) {
  if (!str) return '';
  const clean = String(str)
    .toUpperCase()
    .replace(/[^A-Z\s]/g, ' ')
    .trim();
  const words = clean.split(/\s+/).filter(Boolean).sort();
  return words.join(' ');
}

function lookupGovernmentRecord({ docType, nid }) {
  const registry = loadRegistry();
  const nidClean = String(nid || '').replace(/[^A-Z0-9]/gi, '').toUpperCase();
  if (!nidClean) return { found: false, reason: 'No ID provided.' };

  // 1. Check Aadhaar (12 digits)
  if (docType === 'AADHAAR' || nidClean.length === 12) {
    const aRecord = registry.aadhaar.find(a => a.uid.replace(/\D/g, '') === nidClean);
    if (aRecord) {
      return { found: true, docType: 'AADHAAR', source: 'UIDAI_GOV_REGISTRY', record: aRecord };
    }
    if (docType === 'AADHAAR') return { found: false, reason: `Aadhaar UID ${nid} not found in UIDAI database.` };
  }

  // 2. Check PAN Card (10 chars, format: 5 letters, 4 digits, 1 letter)
  const isPan = docType === 'PAN' || /^[A-Z]{5}[0-9]{4}[A-Z]$/.test(nidClean);
  if (isPan) {
    const pRecord = (registry.pan || []).find(p => p.panNumber.replace(/[^A-Z0-9]/gi, '').toUpperCase() === nidClean);
    if (pRecord) {
      return { found: true, docType: 'PAN', source: 'NSDL_PAN_REGISTRY', record: pRecord };
    }
    if (docType === 'PAN') return { found: false, reason: `PAN card ${nid} not found in Income Tax / NSDL database.` };
  }

  // 3. Check Passport
  const passRecord = registry.passports.find(p => p.passportNumber.replace(/[^A-Z0-9]/gi, '').toUpperCase() === nidClean);
  if (passRecord) {
    return { found: true, docType: 'PASSPORT', source: 'PASSPORT_SEVA_REGISTRY', record: passRecord };
  }

  return { found: false, reason: `Document ID ${nid} was not found in official government records.` };
}

function registerGovernmentRecord({ docType, nid, name, dob, address, gender, expiry }) {
  const registry = loadRegistry();
  const nidClean = String(nid || '').replace(/[^A-Z0-9]/gi, '').toUpperCase();
  const cleanName = String(name || '').trim();
  const dobNum = parseInt(String(dob || '').replace(/\D/g, ''), 10) || undefined;

  if (!nidClean || !cleanName) {
    return { ok: false, reason: 'Both document ID and Full Name are required for registration.' };
  }

  const type = docType ? docType.toUpperCase() : (nidClean.length === 12 ? 'AADHAAR' : (/^[A-Z]{5}[0-9]{4}[A-Z]$/.test(nidClean) ? 'PAN' : 'PASSPORT'));

  if (type === 'AADHAAR') {
    const existing = registry.aadhaar.find(a => a.uid.replace(/\D/g, '') === nidClean);
    if (existing) {
      existing.name = cleanName;
      if (dobNum) existing.dob = dobNum;
      if (address) existing.address = address;
    } else {
      registry.aadhaar.push({
        uid: nidClean,
        name: cleanName,
        dob: dobNum,
        gender: gender || 'M',
        address: address || 'India',
        status: 'ACTIVE'
      });
    }
  } else if (type === 'PAN') {
    registry.pan = registry.pan || [];
    const existing = registry.pan.find(p => p.panNumber.replace(/[^A-Z0-9]/gi, '').toUpperCase() === nidClean);
    if (existing) {
      existing.name = cleanName;
      if (dobNum) existing.dob = dobNum;
      if (address) existing.address = address;
    } else {
      registry.pan.push({
        panNumber: nidClean,
        name: cleanName,
        dob: dobNum,
        gender: gender || 'M',
        address: address || 'India',
        status: 'ACTIVE'
      });
    }
  } else {
    // Passport
    const existing = registry.passports.find(p => p.passportNumber.replace(/[^A-Z0-9]/gi, '').toUpperCase() === nidClean);
    if (existing) {
      existing.name = cleanName;
      if (dobNum) existing.dob = dobNum;
      if (address) existing.address = address;
    } else {
      registry.passports.push({
        passportNumber: nidClean,
        name: cleanName,
        dob: dobNum,
        expiry: parseInt(String(expiry || '').replace(/\D/g, ''), 10) || 20351231,
        nationality: 'IND',
        gender: gender || 'M',
        address: address || 'India',
        status: 'ACTIVE'
      });
    }
  }

  saveRegistry(registry);
  return {
    ok: true,
    message: `Document ${nidClean} successfully registered in official government database for ${cleanName}.`,
    docType: type,
    record: { uid: nidClean, name: cleanName, dob: dobNum, address }
  };
}

function verifyGovernmentRecord({ docType, nid, name, dob }) {
  const registry = loadRegistry();
  const nidClean = String(nid || '').replace(/[^A-Z0-9]/gi, '').toUpperCase();
  const nameNorm = normalizeName(name);
  const dobNum = parseInt(String(dob || '').replace(/\D/g, ''), 10);

  if (!nidClean) {
    return {
      ok: false,
      error: 'MISSING_NID',
      reason: 'National ID / Document number is required.'
    };
  }
  if (!nameNorm) {
    return {
      ok: false,
      error: 'MISSING_NAME',
      reason: 'Full name is required to verify identity against government registry.'
    };
  }

  // 1. Check Aadhaar (12 digits)
  const isAadhaar = docType === 'AADHAAR' || (docType !== 'PASSPORT' && docType !== 'PAN' && nidClean.length === 12);

  if (isAadhaar) {
    const record = registry.aadhaar.find(a => a.uid.replace(/\D/g, '') === nidClean);
    if (!record) {
      return {
        ok: false,
        error: 'UID_NOT_FOUND',
        reason: `Aadhaar UID ${nid} was not found in official UIDAI database.`
      };
    }
    const recordNameNorm = normalizeName(record.name);
    if (nameNorm !== recordNameNorm) {
      return {
        ok: false,
        error: 'NAME_MISMATCH',
        reason: 'Name does not match official UIDAI records for this UID.'
      };
    }
    if (dobNum && record.dob && dobNum !== record.dob) {
      return {
        ok: false,
        error: 'DOB_MISMATCH',
        reason: 'Date of Birth does not match official UIDAI records.'
      };
    }
    return {
      ok: true,
      source: 'UIDAI_GOV_REGISTRY',
      record
    };
  }

  // 2. Check PAN Card (10 chars alphanumeric)
  const isPan = docType === 'PAN' || (docType !== 'PASSPORT' && /^[A-Z]{5}[0-9]{4}[A-Z]$/.test(nidClean));
  if (isPan) {
    const panRecord = (registry.pan || []).find(p => p.panNumber.replace(/[^A-Z0-9]/gi, '').toUpperCase() === nidClean);
    if (!panRecord) {
      return {
        ok: false,
        error: 'PAN_NOT_FOUND',
        reason: `PAN number ${nid} was not found in Income Tax / NSDL database.`
      };
    }
    const panNameNorm = normalizeName(panRecord.name);
    if (nameNorm !== panNameNorm) {
      return {
        ok: false,
        error: 'NAME_MISMATCH',
        reason: 'Name does not match official Income Tax / NSDL records for this PAN card.'
      };
    }
    if (dobNum && panRecord.dob && dobNum !== panRecord.dob) {
      return {
        ok: false,
        error: 'DOB_MISMATCH',
        reason: 'Date of Birth does not match official Income Tax records.'
      };
    }
    return {
      ok: true,
      source: 'NSDL_PAN_REGISTRY',
      record: panRecord
    };
  }

  // 3. Check Passport or other registered document
  const passRecord = registry.passports.find(p => p.passportNumber.replace(/[^A-Z0-9]/gi, '').toUpperCase() === nidClean);
  if (passRecord) {
    const passNameNorm = normalizeName(passRecord.name || (passRecord.givenNames + ' ' + passRecord.surname));
    if (nameNorm !== passNameNorm) {
      return {
        ok: false,
        error: 'NAME_MISMATCH',
        reason: 'Name does not match official records for this passport.'
      };
    }

    if (dobNum && passRecord.dob && dobNum !== passRecord.dob) {
      return {
        ok: false,
        error: 'DOB_MISMATCH',
        reason: 'Date of Birth does not match official passport records.'
      };
    }

    return {
      ok: true,
      source: 'PASSPORT_SEVA_REGISTRY',
      record: passRecord
    };
  }

  if (docType === 'PASSPORT') {
    return {
      ok: false,
      error: 'PASSPORT_NOT_FOUND',
      reason: `Passport number ${nid} was not found in Ministry of External Affairs / Passport Seva database.`
    };
  }

  return {
    ok: false,
    error: 'RECORD_NOT_FOUND',
    reason: `Document ID ${nid} was not found in any official government identity database.`
  };
}

module.exports = {
  loadRegistry,
  saveRegistry,
  normalizeName,
  lookupGovernmentRecord,
  registerGovernmentRecord,
  verifyGovernmentRecord
};
