<?php

namespace App\Livewire;

use Illuminate\Support\Facades\Http;
use Livewire\Component;

class ArticleImagePreview extends Component
{
    public $imageUrl = '';
    public $imageData = '';
    public $isLoading = false;

    public function updatedImageUrl()
    {
        $this->imageData = '';
        $this->isLoading = false;

        if (!$this->imageUrl) {
            return;
        }

        $this->isLoading = true;

        try {
            $url = $this->imageUrl;

            /*
            |--------------------------------------------------------------------------
            | 1. Validate URL
            |--------------------------------------------------------------------------
            */

            $parsed = parse_url($url);

            if (
                !$parsed ||
                !isset($parsed['scheme']) ||
                !isset($parsed['host'])
            ) {
                throw new \InvalidArgumentException('Invalid URL');
            }

            /*
            |--------------------------------------------------------------------------
            | 2. Only HTTPS
            |--------------------------------------------------------------------------
            */

            if (strtolower($parsed['scheme']) !== 'https') {
                throw new \InvalidArgumentException(
                    'Only HTTPS URLs are allowed'
                );
            }

            /*
            |--------------------------------------------------------------------------
            | 3. Domain allowlist
            |--------------------------------------------------------------------------
            */

            $allowedDomains = [
                'placehold.co',
            ];

            $host = strtolower($parsed['host']);

            if (!in_array($host, $allowedDomains, true)) {
                throw new \InvalidArgumentException(
                    'Domain not allowed'
                );
            }

            /*
            |--------------------------------------------------------------------------
            | 4. Block private and reserved IP addresses
            |--------------------------------------------------------------------------
            */

            $ip = gethostbyname($host);

            if (
                !filter_var(
                    $ip,
                    FILTER_VALIDATE_IP,
                    FILTER_FLAG_NO_PRIV_RANGE |
                    FILTER_FLAG_NO_RES_RANGE
                )
            ) {
                throw new \InvalidArgumentException(
                    'Private or reserved addresses are not allowed'
                );
            }

            /*
            |--------------------------------------------------------------------------
            | 5. Safe HTTP request
            |--------------------------------------------------------------------------
            */

            $response = Http::timeout(5)
                ->withOptions([
                    'allow_redirects' => false,
                    'verify' => true,
                ])
                ->get($url);

            if (!$response->successful()) {
                throw new \InvalidArgumentException(
                    'Remote server returned an invalid response'
                );
            }

            /*
            |--------------------------------------------------------------------------
            | 6. Validate Content-Type
            |--------------------------------------------------------------------------
            */

            $contentType = $response->header('Content-Type');

            if (!$contentType) {
                throw new \InvalidArgumentException(
                    'Missing content type'
                );
            }

            $contentType = strtolower(
                trim(explode(';', $contentType)[0])
            );

            $allowedTypes = [
                'image/jpeg',
                'image/png',
                'image/gif',
                'image/webp',
            ];

            if (!in_array($contentType, $allowedTypes, true)) {
                throw new \InvalidArgumentException(
                    'Content type not allowed'
                );
            }

            /*
            |--------------------------------------------------------------------------
            | 7. Limit response size to 1 MB
            |--------------------------------------------------------------------------
            */

            $body = $response->body();

            if (strlen($body) > 1024 * 1024) {
                throw new \InvalidArgumentException(
                    'Response too large'
                );
            }

            /*
            |--------------------------------------------------------------------------
            | Valid external image
            |--------------------------------------------------------------------------
            */

            $this->imageData =
                'data:' .
                $contentType .
                ';base64,' .
                base64_encode($body);

        } catch (\Exception $e) {

            $this->addError(
                'imageUrl',
                'Error loading image: ' . $e->getMessage()
            );

        } finally {

            $this->isLoading = false;

        }
    }

    public function clearImage()
    {
        $this->imageUrl = '';
        $this->imageData = '';
        $this->isLoading = false;
        $this->resetErrorBag();
    }

    public function render()
    {
        return view('livewire.article-image-preview');
    }
}