/**
 * Recursively converts all BigInt values in an object to strings
 * This is necessary because JSON.stringify cannot serialize BigInt values
 * @param {any} obj - The object to serialize
 * @returns {any} - The object with all BigInt values converted to strings
 */
const serializeBigInt = (obj) => {
  if (obj === null || obj === undefined) {
    return obj;
  }

  // Handle BigInt directly
  if (typeof obj === 'bigint') {
    return obj.toString();
  }

  // Handle arrays
  if (Array.isArray(obj)) {
    return obj.map(serializeBigInt);
  }

  // Handle objects
  if (typeof obj === 'object') {
    const serialized = {};
    for (const [key, value] of Object.entries(obj)) {
      serialized[key] = serializeBigInt(value);
    }
    return serialized;
  }

  // Return primitive values as-is
  return obj;
};

module.exports = {
  serializeBigInt,
};

