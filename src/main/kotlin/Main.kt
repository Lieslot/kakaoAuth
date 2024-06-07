package org.example

import org.apache.commons.cli.DefaultParser
import org.apache.commons.cli.Options
import org.apache.commons.cli.ParseException
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

data class KdfResult(val key: ByteArray, val iv: ByteArray)
data class MixOutResult(val salt: ByteArray, val enc: ByteArray)

fun createSalt(size: Int): ByteArray {
    val random = SecureRandom.getInstance("SHA1PRNG")
    return random.generateSeed(size)
}

fun openSslKdf(
    passphrase: String,
    salt: ByteArray,
    keySize: Int = 32,
    ivSize: Int = 16,
    iterations: Int = 1,
    hash: MessageDigest = MessageDigest.getInstance("MD5"),
): KdfResult {
    val totalSize = keySize + ivSize
    val result = mutableListOf<Byte>()
    val passphrase = passphrase.toByteArray()

    var block: ByteArray? = null

    while (result.size < totalSize) {
        if (block != null) {
            hash.update(block)
        }
        hash.update(passphrase)
        block = hash.digest(salt)
        hash.reset()
        for (i in 1..<iterations) {
            block = hash.digest(block)
            hash.reset()
        }
        block?.toList()?.let { result.addAll(it) }
    }
    result.toByteArray().let {
        return KdfResult(it.copyOfRange(0, keySize), it.copyOfRange(keySize, totalSize))
    }
}

fun saltPrefix(): ByteArray = "Salted__".toByteArray()

@OptIn(ExperimentalEncodingApi::class)
fun mixIn(salt: ByteArray, enc: ByteArray) = Base64.encode(saltPrefix() + salt + enc)

@OptIn(ExperimentalEncodingApi::class)
fun mixOut(encrypted: String, saltSize: Int = 8): MixOutResult {
    val decoded = Base64.decode(encrypted)
    val pfx = saltPrefix()
    if (!decoded.copyOfRange(0, pfx.size).contentEquals(pfx)) {
        throw IllegalArgumentException("Salt prefix mismatch")
    }
    return MixOutResult(
        decoded.copyOfRange(pfx.size, pfx.size + saltSize), decoded.copyOfRange(pfx.size + saltSize, decoded.size)
    )
}

fun encrypt(plain: String, passphrase: String): String {
    val salt = createSalt(8)
    val (key, iv) = openSslKdf(passphrase, salt)

    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val keySpec = SecretKeySpec(key, "AES")
    val ivSpec = IvParameterSpec(iv)

    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
    val enc = cipher.doFinal(plain.toByteArray())
    return mixIn(salt, enc)
}

fun decrypt(encrypted: String, passphrase: String) : ByteArray {
    val (salt, enc) = mixOut(encrypted)
    val (key, iv) = openSslKdf(passphrase, salt)

    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val keySpec = SecretKeySpec(key, "AES")
    val ivSpec = IvParameterSpec(iv)

    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
    val dec = cipher.doFinal(enc)
    return dec
}

fun printUsage(appName: String) {
    println("usage: \n\t./$appName -e <message> -p <passphrase>\n\t./$appName -d <encrypted_message> -p <passphrase>")
}

fun main(args : Array<String>) {
    val appName = Class.forName("org.example.MainKt")
        .protectionDomain
        .codeSource
        .location
        .toURI()
        .path
        .substringAfterLast("/")

    val options = Options()
        .addOption("e", "encrypt", true, "message to encrypt")
        .addOption("d", "decrypt", true, "message to decrypt")
        .addRequiredOption("p", "passphrase", true, "this is mandatory. passphrase for encryption/decryption")

    val parser = DefaultParser()

    try {
        val cmd = parser.parse(options, args)
        if (cmd.hasOption("e") && cmd.hasOption("d")) {
            throw ParseException("duplicated mode ;(")
        }
        else if (cmd.hasOption("e")) {
            val message = cmd.getOptionValue("e")
            val passphrase = cmd.getOptionValue("p")
            println(encrypt(message, passphrase))
        }
        else if (cmd.hasOption("d")) {
            val message = cmd.getOptionValue("d")
            val passphrase = cmd.getOptionValue("p")
            println(String(decrypt(message, passphrase)))
        }
        else {
            throw ParseException("no specification for mode")
        }
    } catch (e: ParseException) {
        printUsage(appName)
        println("hello")
    }
}
