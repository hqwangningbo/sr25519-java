package com.wangningbo.utils;

import com.google.common.collect.Lists;
import com.google.common.primitives.UnsignedBytes;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.crypto.digests.Blake2bDigest;

import java.lang.reflect.Array;
import java.math.BigInteger;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class Utils {

    static final String HEX_REGEX = "^0x[a-fA-F0-9]+$";
    public static boolean isHex(Object value) {
        return isHex(value, -1, false);
    }
    public static boolean isHex(Object value, int bitLength, boolean ignoreLength) {
        if (value == null) {
            return false;
        }
        //CharSequence value = _value.toString();
        boolean isValidHex = value.equals("0x") || (value instanceof String && Pattern.matches(HEX_REGEX, (CharSequence) value));

        if (isValidHex && bitLength != -1) {
            String strValue = (String) value;
            return strValue.length() == (2 + (int) Math.ceil(bitLength / 4));
        }

        return isValidHex && (ignoreLength || (((String) value).length() % 2 == 0));
    }
    public static byte[] hexToU8a(String value, int bitLength) {
        if (value == null) {
            return new byte[0];
        }

        assert isHex(value) : "Expected hex value to convert, found " + value;

        value = hexStripPrefix(value);
        int valLength = value.length() / 2;
        int bufLength = (int) Math.ceil((
                bitLength == -1
                        ? valLength
                        : bitLength / 8f));

        byte[] result = new byte[bufLength];
        int offSet = Math.max(0, bufLength - valLength);

        for (int index = 0; index < bufLength; index++) {
            String byteStr = value.substring(index * 2, index * 2 + 2);
            result[index + offSet] = UnsignedBytes.parseUnsignedByte(byteStr, 16);
        }
        return result;
    }
    public static byte[] hexToU8a(String value) {
        return hexToU8a(value, -1);
    }

    static String UNPREFIX_HEX_REGEX = "^[a-fA-F0-9]+$";

    public static String hexStripPrefix(String value) {
        if (value == null) {
            return "";
        }

        if (hexHasPrefix(value)) {
            return value.substring(2);
        }

        if (Pattern.matches(UNPREFIX_HEX_REGEX, value)) {
            return value;
        }

        throw new RuntimeException("Invalid hex " + value + " passed to hexStripPrefix");
    }
    public static boolean hexHasPrefix(String value) {
        if (value != null
                && isHex(value, -1, true)
                && value.substring(0, 2).equals("0x")) {
            return true;
        }
        return false;
    }

    public static BigInteger hexToBn(Object value, boolean isLe, boolean isNegative) {
        if (value == null) {
            return BigInteger.ZERO;
        }

        String rawValue = hexStripPrefix((String) value);

        if (isLe) {
            //"12345678" --- "78563412"
            StringBuilder reverse = new StringBuilder(rawValue).reverse();
            for (int i = 0; i < reverse.length(); i += 2) {
                char c1 = reverse.charAt(i);
                char c2 = reverse.charAt(i + 1);

                reverse.setCharAt(i + 1, c1);
                reverse.setCharAt(i, c2);
            }
            rawValue = reverse.toString();
        }

        BigInteger bigInteger = BigInteger.ZERO;
        if (rawValue.length() > 0){
            bigInteger = new BigInteger(rawValue, 16);
        }
        //BigInteger bigInteger = new BigInteger(rawValue, 16);

        if (isNegative) {
            //TODO 2019-05-08 23:04
            throw new UnsupportedOperationException();
        }
        return bigInteger;

        // FIXME: Use BN's 3rd argument `isLe` once this issue is fixed
        // https://github.com/indutny/bn.js/issues/208
        //const bn = new BN((_options.isLe ? reverse(_value) : _value) || '00', 16);

        // fromTwos takes as parameter the number of bits, which is the hex length
        // multiplied by 4.
        //return _options.isNegative ? bn.fromTwos(_value.length * 4) : bn;
    }
    public static BigInteger u8aToBn(byte[] value, boolean isLe, boolean isNegative) {
        return hexToBn(
                u8aToHex(value),
                isLe, isNegative
        );
    }
    public static BigInteger bnToBn(Object value) {
        if (value == null) {
            return BigInteger.ZERO;
        }

        if (value instanceof BigInteger) {
            return (BigInteger) value;
        } else if (value instanceof Number) {
            return new BigInteger(value.toString());
        } else if (value instanceof String) {
            return new BigInteger((String) value, 16);
        }

        throw new RuntimeException(" bnToBn " + value);
    }
    final static String ZERO_STR = "0x00";
    public static String bnToHex(BigInteger value, int bitLength) {
        return bnToHex(value, false, false, bitLength);
    }
    public static String bnToHex(BigInteger value, boolean isLe, boolean isNegtive, int bitLength) {
        if (value == null) {
            return ZERO_STR;
        }

        return u8aToHex(bnToU8a(value, isLe, isNegtive, bitLength));
    }
    public static byte[] bnToU8a(BigInteger value, boolean isLe, int bitLength) {
        return bnToU8a(value, isLe, false, bitLength);
    }
    public static byte[] bnToU8a(BigInteger value, boolean isLe, boolean isNegative, int bitLength) {
        BigInteger valueBn = bnToBn(value);
        int byteLength;
        if (bitLength == -1) {
            byteLength = (int) Math.ceil(valueBn.bitLength() / 8f);
        } else {
            byteLength = (int) Math.ceil(bitLength / 8f);
        }

        if (value == null) {
            if (bitLength == -1) {
                return new byte[0];
            } else {
                return new byte[byteLength];
            }
        }

        byte[] output = new byte[byteLength];

        if (isNegative) {
            //TODO  valueBn.negate()
            //const bn = _options.isNegative ? valueBn.toTwos(byteLength * 8) : valueBn;
        }

        if (isLe) {
            byte[] bytes = toByteArrayLittleEndianUnsigned(valueBn);
            //arraycopy(Object src,  int  srcPos,
            //Object dest, int destPos,
            //int length);
            System.arraycopy(bytes, 0, output, 0, bytes.length);
        } else {
            //big-endian
            byte[] bytes = valueBn.toByteArray();
            System.arraycopy(bytes, 0, output, output.length - bytes.length, bytes.length);
        }
        //if (output.length != bytes.length) {
        //    throw new RuntimeException();
        //}

        return output;

    }
    public static byte[] toByteArrayLittleEndianUnsigned(BigInteger bi) {
        byte[] extractedBytes = toByteArrayUnsigned(bi);
        ArrayUtils.reverse(extractedBytes);
        //byte[] reversed = ByteUtils.reverseArray(extractedBytes);
        return extractedBytes;
    }
    public static byte[] toByteArrayUnsigned(BigInteger bi) {
        byte[] extractedBytes = bi.toByteArray();
        int skipped = 0;
        boolean skip = true;
        for (byte b : extractedBytes) {
            boolean signByte = b == (byte) 0x00;
            if (skip && signByte) {
                skipped++;
                continue;
            } else if (skip) {
                skip = false;
            }
        }
        extractedBytes = Arrays.copyOfRange(extractedBytes, skipped,
                extractedBytes.length);
        return extractedBytes;
    }
    public static Pair<Integer, BigInteger> compactFromU8a(Object _input, int bitLength) {
        byte[] input = u8aToU8a(_input);
        int flag;
        if (input.length == 0) {
            return Pair.of(1, new BigInteger("0").shiftRight(2));
        } else {
            flag = UnsignedBytes.toInt(input[0]) & 0b11;
        }

        if (flag == 0b00) {
            //shift right
            return Pair.of(1, new BigInteger(UnsignedBytes.toInt(input[0]) + "").shiftRight(2));
        } else if (flag == 0b01) {
            byte[] subarray = ArrayUtils.subarray(input, 0, 2);
            return Pair.of(2, u8aToBn(subarray, true, false).shiftRight(2));
        } else if (flag == 0b10) {
            byte[] subarray = ArrayUtils.subarray(input, 0, 4);
            return Pair.of(4, u8aToBn(subarray, true, false).shiftRight(2));
        }


        int length = BigInteger.valueOf(UnsignedBytes.toInt(input[0]))
                .shiftRight(2)
                .add(BigInteger.valueOf(4))
                .intValue();

        int offset = length + 1;
        return Pair.of(offset, u8aToBn(ArrayUtils.subarray(input, 1, offset), true, false));
    }
    public static Pair<Integer, BigInteger> compactFromU8a(Object input) {
        return compactFromU8a(input, 32);
    }
    public static String u8aToString(byte[] value) {
        if (value == null || value.length == 0) {
            return "";
        }


        StringBuilder sb = new StringBuilder();
        for (byte b : value) {
            char ch = (char) UnsignedBytes.toInt(b);
            sb.append(ch);
        }

        //TODO 2019-05-14 02:49 uint8

//  return decoder.decode(value);
        return new String(value);
        //return sb.toString();
    }

    static final String ALPHABET = "0123456789abcdef";
    public static String u8aToHex(byte[] value, int bitLength, boolean isPrefixed) {
        String prefix = isPrefixed ? "0x" : "";

        if (ArrayUtils.isEmpty(value)) {
            return prefix;
        }

        int byteLength = (int) Math.ceil(bitLength / 8f);

        if (byteLength > 0 && value.length > byteLength) {
            int halfLength = (int) Math.ceil(byteLength / 2f);

            String left = u8aToHex(ArrayUtils.subarray(value, 0, halfLength), -1, isPrefixed);
            String right = u8aToHex(ArrayUtils.subarray(value, value.length - halfLength, value.length), -1, false);

            return left + "..." + right;
        }
        StringBuilder stringBuilder = new StringBuilder(prefix);

        for (byte b : value) {
            int ub = UnsignedBytes.toInt(b);
            stringBuilder.append(ALPHABET.charAt(ub >> 4)).append(ALPHABET.charAt(ub & 15));
        }
        return stringBuilder.toString();
    }
    public static String u8aToHex(byte[] value) {
        return u8aToHex(value, -1, true);
    }
    public static byte[] stringToU8a(String value) {
        if (StringUtils.isEmpty(value)) {
            return new byte[0];
        }
        //TODO 2019-05-09 00:48 test
        return value.getBytes();
    }
    public static byte[] compactAddLength(byte[] input) {
        return u8aConcat(Lists.newArrayList(
                compactToU8a(input.length),
                input)
        );
    }
    final static BigInteger MAX_U8 = BigInteger.valueOf(2).pow(8 - 2).subtract(BigInteger.ONE);
    final static BigInteger MAX_U16 = BigInteger.valueOf(2).pow(16 - 2).subtract(BigInteger.ONE);
    final static BigInteger MAX_U32 = BigInteger.valueOf(2).pow(32 - 2).subtract(BigInteger.ONE);
    public static byte[] compactToU8a(Object _value) {
        BigInteger value = bnToBn(_value);

        if (value.compareTo(MAX_U8) <= 0) {
            return new byte[]{UnsignedBytes.parseUnsignedByte((value.intValue() << 2) + "")};
        } else if (value.compareTo(MAX_U16) <= 0) {
            return bnToU8a(value.shiftLeft(2).add(BigInteger.valueOf(0b01)), true, false, 16);
        } else if (value.compareTo(MAX_U32) <= 0) {
            return bnToU8a(value.shiftLeft(2).add(BigInteger.valueOf(0b10)), true, false, 32);
        }

        byte[] u8a = bnToU8a(value, true, false, -1);
        int length = u8a.length;

        while (u8a[length - 1] == 0) {
            length--;
        }

        assert length >= 4 : "Previous tests match anyting less than 2^30; qed";

        return u8aConcat(Lists.newArrayList(
                // substract 4 as minimum (also catered for in decoding)
                new byte[]{UnsignedBytes.parseUnsignedByte((((length - 4) << 2) + 0b11) + "")},
                ArrayUtils.subarray(u8a, 0, length)
        ));
    }
    public static byte[] u8aConcat(List<byte[]> _list) {
        List<byte[]> list = _list.stream().map(e -> u8aToU8a(e)).collect(Collectors.toList());

        int length = list.stream().mapToInt(e -> e.length).sum();
        byte[] result = new byte[length];
        int offset = 0;

        for (byte[] bytes : list) {
            System.arraycopy(bytes, 0, result, offset, bytes.length);
            offset += bytes.length;
        }
        return result;
    }
    public static byte[] u8aToU8a(Object value) {
        if (value == null) {
            return new byte[0];
        }
        if (value instanceof String) {
            String strValue = (String) value;
            return isHex(strValue)
                    ? hexToU8a(strValue)
                    : stringToU8a(strValue);
        }

        if (value instanceof byte[]) {
            return (byte[]) value;
        }
        if (value.getClass().isArray()) {
            List<Object> objects = arrayLikeToList(value);
            byte[] result = new byte[objects.size()];
            for (int i = 0; i < objects.size(); i++) {
                Number number = (Number) objects.get(i);
                result[i] = UnsignedBytes.parseUnsignedByte(number.toString());
            }
            return result;
        }

        return (byte[]) value;
    }
    public static List<Object> arrayLikeToList(Object value) {
        List<Object> ret = new ArrayList<>();

        if (value == null) {
            return ret;
        }

        if (value instanceof List) {
            for (Object obj : ((List) value)) {
                ret.add(obj);
            }
            return ret;
        } else if (value.getClass().isArray()) {
            Class<?> componentType = value.getClass().getComponentType();
            if (componentType.isPrimitive()) {
                int length = Array.getLength(value);
                for (int i = 0; i < length; i++) {
                    Object obj = Array.get(value, i);
                    ret.add(obj);
                }
            } else {
                Object[] objects = (Object[]) value;
                for (Object obj : objects) {
                    ret.add(obj);
                }
            }
            return ret;
        }
        return ret;
    }
    public static byte[] blake2AsU8a(byte[] data, int bitLength, byte[] key) {
        int byteLength = (int) Math.ceil(bitLength / 8F);
        Blake2bDigest blake2bkeyed = new Blake2bDigest(key, byteLength, null, null);
        blake2bkeyed.reset();
        blake2bkeyed.update(data, 0, data.length);
        byte[] keyedHash = new byte[64];
        int digestLength = blake2bkeyed.doFinal(keyedHash, 0);
        return ArrayUtils.subarray(keyedHash, 0, digestLength);
    }
    public static byte[] blake2AsU8a(byte[] data, int bitLength) {
        return blake2AsU8a(data, bitLength, null);
    }
    final static byte[] SS58_PREFIX = stringToU8a("SS58PRE");
    public static byte[] sshash(byte[] key) {
        return blake2AsU8a(u8aConcat(Lists.newArrayList(SS58_PREFIX, key)), 512);
    }
}
