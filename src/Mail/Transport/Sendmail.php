<?php

namespace UweLehmann\GpgMail\Mail\Transport;

use Zend\Mail;

use UweLehmann\GpgMail\Mail\Message;
use UweLehmann\Gpg\Crypt\PublicKey\Gpg;

/**
 * extends Zend\Mail\Transport\Sendmail to provide GPG signing and encrypting features
 *
 * @author Uwe Lehmann <lehmann.uwe@gmx.de>
 * @copyright (c) 2017, Uwe Lehmann
 */
class Sendmail extends Mail\Transport\Sendmail implements Mail\Transport\TransportInterface
{
    /**
     * @todo do we want multiple encrypted/signed messages?
     *
     * @see \Zend\Mail\Transport\Sendmail::_sendMail()
     * @param \UweLehmann\GpgMail\Mail\Message $message
     * @param \UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key $signKey
     * @param string $password
     * @throws \Zend\Mail\Transport\Exception\RuntimeException
     */
    public function send(Mail\Message $message, Gpg\Key $signKey = null, $password = null)
    {
        if (!$message instanceof Message) {
            throw new Mail\Transport\Exception\InvalidArgumentException('Invalid message type; expecting type "' . Message::class . '", "' . get_class($message) . '" given');
        }

        if ($signKey instanceof Gpg\Key) {

            if ($signKey->getType() != Gpg\Key::TYPE_SECRET) {
                throw new Mail\Transport\Exception\InvalidArgumentException('Invalid signature key; contains non secret key');
            }

            $message->sign($signKey, $password);
        }

        $message->encrypt();

        // send message
        parent::send($message);
    }
}
