# Project Report: NFC ticket design on MIFARE Ultralight C

Design a smart card ticket application for a small operator that uses cheap blank smartcards as the ticket medium, formats the cards when the first tickets are issued to the card, and uses NFC-enabled mobile phones or similar Android devices for the ticket validation.

## Memory Management

The NXP MIFARE Ultralight C smart card, which contains 192 bytes of memory divided into 48 pages of 4 bytes each.

<table>
  <thead>
    <tr>
      <th th colspan="2">Page address</th>
      <th th colspan="4">Byte number</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Decimal</td>
      <td>Hex</td>
      <td>0</td>
      <td>1</td>
      <td>2</td>
      <td>3</td>
    </tr>
    <tr>
      <td>0</td>
      <td>00h</td>
      <td th colspan="4">serial number</td>
    </tr>
    <tr>
      <td>1</td>
      <td>01h</td>
      <td th colspan="4">serial number</td>
    </tr>
    <tr>
      <td>2</td>
      <td>02h</td>
      <td>serial number</td>
      <td>internal</td>
      <td>lock bytes</td>
      <td>lock bytes</td>
    </tr>
    <tr>
      <td>3</td>
      <td>03h</td>
      <td th colspan="4">a one-time programmable page (OTP)</td>
    </tr> 
    <tr>
      <td>4</td>
      <td>04h</td>
      <td th colspan="4">Application Tag</td>
    </tr>    
    <tr>
      <td>5</td>
      <td>05h</td>
      <td th colspan="4">Application Version</td>
    </tr>
    <tr>
      <td>6</td>
      <td>06h</td>
      <td th colspan="4">Expiry Date</td>
    </tr>
    <tr>
      <td>7</td>
      <td>07h</td>
      <td th colspan="4">Number of Rides</td>
    </tr>
    <tr>
      <td>8</td>
      <td>08h</td>
      <td th colspan="4">MAC(User Data(Page 0 - Page 2))</td>
    </tr>
    <tr>
      <td>40</td>
      <td>28h</td>
      <td>lock bytes</td>
      <td>lock bytes</td>
      <td>-</td>
      <td>-</td>
    </tr>
    <tr>
      <td>41</td>
      <td>29h</td>
      <td>16-bit counter</td>
      <td>16-bit counter</td>
      <td>-</td>
      <td>-</td>
    </tr>
    <tr>
      <td>42</td>
      <td>2Ah</td>
      <td>04h</td>
      <td>-</td>
      <td>-</td>
      <td>-</td>
    </tr>
    <tr>
      <td>43</td>
      <td>2Bh</td>
      <td>0000000[0]</td>
      <td>-</td>
      <td>-</td>
      <td>-</td>
    </tr>
    <tr>
      <td>44 to 47</td>
      <td>2Ch to 2Fh</td>
      <td th colspan="4">authentication key = SHA256(UID | "secret message")</td>
    </tr>
  </tbody>
</table>

* Page 3 

Page 3 is a one-time programmable page (OTP) with 32 bits that can be set to one but not reset back to zero. It can be used as a kind of unary counter or for recording other irreversible state changes.

* Page 41 

Page 41 contains two bytes that form a 16-bit counter, which is a newer feature and easier to use than the OTP page.

* Page 42 (AUTH0):
  
AUTH0 defines the page address from which the authentication is required. Valid address values for byte AUTH0 are from 03h to 30h.

* Page 43 (AUTH1):

Table 12. AUTH1 bit description
<table>
  <tr>
    <td>Bit</td>
    <td>Value</td>
    <td>Description</td>
  </tr>
  <tr>
    <td>1 to 7</td>
    <td>any</td>
    <td>ignore</td>
  </tr>
  <tr>
    <td th rowspan="2">0</td>
    <td>1</td>
    <td>write access restricted, read access allowed without authentication.</td>
  </tr>
  <tr>
    <td>0</td>
    <td>read and write access restricted</td>
  </tr>
</table>
  
0000000[0]: Setting the first bit to 0 states that read and write access is restricted from the pages that are specified in AUTH0


## Design  
* Application tag and version number

It is a good idea to reserve one or two pages of the card memory for an application tag and version number. The application tag is simply a constant string that is specific to your application and ticket design. It can be used to quickly identify cards that have been initialized for this specific application. **If the correct application tag is found on the card, it is reasonable to assume that the authentication key has been changed to the application-specific (and diversified) key.** On the other hand, if the application tag is not found on the card, it may be a blank card that can be formatted for your application. In that case, the authentication key should still have the manufacturer’s default value. It could also be that the card has been initialized for an entirely different application. In commercial systems, you would want to check that the card is blank before formatting it and reject any previously used cards. During software development and in non-professional use, you may want to recycle as many cards as possible. **To reuse a card, you need to know the card key, and you need to check that the values of the lock bits, OTP and counter are in acceptable initial state for your application.**

The version number field will be helpful later when you update the data-structure specification. It enables multiple versions of the ticket to co-exist during a transition period.

## Security Concerns

* Key diversification, event logging, and misuse detection

To prevent the large-scale security failure caused by breaking of one card, it is better to use a different secret key for each card. This is done by **computing the diversified (i.e. per-card) key as K = h(master secret | UID)** where h is a cryptographic hash function, UID is the unique 7-byte identifier of the card, and the master secret is stored only on the reader side (preferably in a physical security module or in an online server).

* Message authentication code (MAC) on ticket data

To prevent the MitM attacks on the Ultralight family cards, you can **compute a message authentication code (MAC) over the ticket data on the card, including the card UID, and write the MAC to the card.** The reader should then verify the MAC when reading the ticket data. This prevents arbitrary modifications to the card data by the MitM attacker. Instead of including the UID into the MAC input, you can also compute the MAC with a diversified key.

The MAC does not need to be very long. If the attacker tries to create a correct MAC by brute-force guessing, it will need to tap the physical card reader after each guessed value to find out of the guess is correct. Depending on the application, **just 4 bytes of MAC may be sufficient:** the attacker will have to tap the reader 2^31 times, on the average, in order to make one malicious change to the card contents.Moreover, if the MAC is bound to the card UID, the produced false content cannot be reused on other cards, with makes such brute-force trials pointless for the attacker. In high-value applications (such as key cards to a treasure vault), the MAC should be slightly longer, but then it makes sense to use a more expensive smart card, instead.

It is usually not necessary to update the MAC when the card is validated. Instead, **compute the MAC only on the issued ticket and exclude the ride counter and other continuously changing data from the MAC input**. For example, the number of remaining rides can be calculated as the difference between the current counter value and an unchanging maximum value. The reasons for not updating the MAC are explained below in the Tearing section.

## Issue Ticket
* we authenticate the card using the default authentication key
* Then we format the card, which contains the following operation:
  *   Issue new authentication key: Hash (UID(serial number) + "secret message")).
  *   Issue application tag and version number.
  *   Clear expiration date and number of rides.
  *   Issue tickets with constant number of rides (5)
  *   Issue MAC over UID.
