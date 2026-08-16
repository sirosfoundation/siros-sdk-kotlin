package org.siros.sdk.sample

import android.app.Application
import coil.ImageLoader
import coil.ImageLoaderFactory
import coil.decode.SvgDecoder
import timber.log.Timber

class SampleApplication : Application(), ImageLoaderFactory {
    override fun onCreate() {
        super.onCreate()
        Timber.plant(Timber.DebugTree())
    }

    /**
     * Coil's default ImageLoader has no SVG decoder - issuer-published
     * credential logos are frequently SVG (github/wwwallet.org-hosted files,
     * inline data: URIs), so any plain AsyncImage/SubcomposeAsyncImage call
     * that doesn't build its own SvgDecoder-equipped loader silently fails
     * to render them and falls back to its placeholder. Registering it here
     * covers every such call site app-wide (confirmed missing via live
     * device testing on AddCredentialScreen's logo badges).
     */
    override fun newImageLoader(): ImageLoader =
        ImageLoader.Builder(this)
            .components { add(SvgDecoder.Factory()) }
            .build()
}
