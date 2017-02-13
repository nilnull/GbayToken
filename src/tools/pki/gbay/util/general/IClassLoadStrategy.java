
package tools.pki.gbay.util.general;

// ----------------------------------------------------------------------------
/**
 * The interface implemented by any classloader selection Strategy used
 * with {@link ClassLoaderResolver} API.
 * 
 * @see DefaultClassLoadStrategy
 * 
 */
public
interface IClassLoadStrategy
{
    // public: ................................................................
    
    /**
     * Selects a classloader based on a given load context.
     * 
     * @see ClassLoaderResolver#getClassLoader()
     */
    ClassLoader getClassLoader (ClassLoadContext ctx);

} // end of interface
// ----------------------------------------------------------------------------