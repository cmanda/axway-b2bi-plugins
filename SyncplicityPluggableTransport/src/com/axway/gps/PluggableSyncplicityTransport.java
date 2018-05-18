/**==============================================================================
 * Program/Module :     PluggableSyncplicityTransport.java
 * Description :       	Pluggable transport that implements the Syncplicity APIs
 * Supported Products :	B2Bi 2.x
 * Author :				Bas van den Berg
 * Copyright :          Axway
 *==============================================================================
 * HISTORY
 * 20180506 bvandenberg	1.0.0	initial version.
 *==============================================================================*/

package com.axway.gps;

import com.cyclonecommerce.tradingengine.transport.UnableToConnectException;
import com.cyclonecommerce.tradingengine.transport.UnableToAuthenticateException;
import com.cyclonecommerce.tradingengine.transport.UnableToConsumeException;
import com.cyclonecommerce.tradingengine.transport.UnableToProduceException;
import com.cyclonecommerce.api.inlineprocessing.Message;
import com.cyclonecommerce.collaboration.MetadataDictionary;
import com.cyclonecommerce.tradingengine.transport.FileNotFoundException;
import com.cyclonecommerce.tradingengine.transport.UnableToDeleteException;
import com.cyclonecommerce.tradingengine.transport.UnableToDisconnectException;
import com.cyclonecommerce.tradingengine.transport.TransportTestException;
import com.cyclonecommerce.tradingengine.transport.TransportInitializationException;
import com.cyclonecommerce.tradingengine.transport.pluggable.api.PluggableClient;
import com.cyclonecommerce.tradingengine.transport.pluggable.api.PluggableException;
import com.cyclonecommerce.tradingengine.transport.pluggable.api.PluggableSettings;
import com.cyclonecommerce.util.VirtualData;
import com.cyclonecommerce.tradingengine.transport.pluggable.api.PluggableMessage;
import util.PluginConstants;
import util.pattern.PatternKeyValidator;
import util.pattern.PatternKeyValidatorFactory;

import entities.File;
import entities.Folder;
import entities.FolderStatus;
import entities.StorageEndpoint;
import entities.SyncPoint;
import oauth.OAuth;
import services.FileService;
import services.FolderService;
import services.StorageEndpointService;
import services.SyncPointService;
import util.APIContext;
import util.APIGateway;

import java.net.Authenticator;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Map;
import java.util.Iterator;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Properties;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.log4j.Level;


public class PluggableSyncplicityTransport implements PluggableClient {
	
	//Set program name and version
	String _PGMNAME = com.axway.gps.PluggableSyncplicityTransport.class.getName();
	String _PGMVERSION = "1.0.0";
	
	/** Constants defining valid configuration tags 
	 *  These tags must NOT contain space or special characters. They MUST match the name element in the pluggabletransports.xml EXACTLY
	 * **/
	private static final String SETTING_APPKEY = "App Key";
	private static final String SETTING_APPSECRET = "App Secret";
	private static final String SETTING_ADMINTOKEN = "Admin Token";
	private static final String SETTING_FOLDERNAME = "Folder";
	private static final String SETTING_PICKUP_PATTERN = "Filter";
	private static final String SETTING_PATTERN_TYPE = "Filter Type";
	private static final String SETTING_DELETE = "Delete After Consumption";

	// Setting to distinguish pickup and delivery mode
	private static final String SETTING_EXCHANGE_TYPE = "Exchange Type";

	
    private static SyncPoint createdSyncPoint;
    private static Folder createdFolder;
    private static File uploadedFile;
 	
	
	//this is how you get the log4J logger instance for this class
	private static Logger logger = Logger.getLogger(com.axway.gps.PluggableSyncplicityTransport.class.getName());

	/** a Map containing temporary Message metadata **/
	private Map metadata = null;
	
	//Stores the settings from the UI
	private String _appkey;
	private String _appsecret;
	private String _admintoken;
	private String _folder;
	private String _filter;
	private String _filtertype;
	private String _exchangeType;
	private String _deleteAfterConsumption;
	
    String messageContent = null;
	private String OathParam[] = new String[3];
	
	Properties env = null;


	//Map containing constant settings from pluggabletransport.xml
	private Map<String,String> constantProperties = null;
	

	/**
	 * Default constructor - the only constructor used by B2Bi
	 */
	public PluggableSyncplicityTransport() {
		
		//Set a default logger level
		if(logger.getLevel() == null) {
			logger.setLevel(Level.INFO);
		}
		logger.info(String.format("Executing PluggableTransport: %s version: %s",_PGMNAME,_PGMVERSION));
	}

	/**
	 * Initialize the pluggable client instance.
	 *
	 * @param pluggableSettings the settings provided by GUI configuration or in the pluggabletransports.xml
	 */
	public void init(PluggableSettings pluggableSettings) throws TransportInitializationException {
		
		try {

			// Get all constant settings from the pluggabletransport.xml file and store 
			// them in the local map for later use
			
			constantProperties = new HashMap<String,String>(pluggableSettings.getConstantSettings());
			if (constantProperties != null && !constantProperties.isEmpty()) {
				Iterator<String> i = constantProperties.keySet().iterator();
				while (i.hasNext()) {
					String key = (String) i.next();
					// logger.debug("Constant setting " + key + "=" + constantProperties.get(key));
				}
			}			
			_exchangeType = pluggableSettings.getConstantSetting(SETTING_EXCHANGE_TYPE);
			
			// Get all settings defined in the GUI for each pluggable transport defined
			
			_appkey = pluggableSettings.getSetting(SETTING_APPKEY);
			_appsecret = pluggableSettings.getSetting(SETTING_APPSECRET);
			_admintoken = pluggableSettings.getSetting(SETTING_ADMINTOKEN);
			_folder = pluggableSettings.getSetting(SETTING_FOLDERNAME);
			
			
			if (_exchangeType.equals("pickup")) {
				_filtertype = pluggableSettings.getSetting(SETTING_PATTERN_TYPE);
				_filter = pluggableSettings.getSetting(SETTING_PICKUP_PATTERN);
				_deleteAfterConsumption = pluggableSettings.getSetting(SETTING_DELETE);
				
			}
				
			OathParam[0] = _appkey;
			OathParam[1] = _appsecret;
			OathParam[2] = _admintoken;
			
			// Sanitize the folder name (remove leading / if provided)
			
			_folder = _folder.startsWith("/") ? _folder.substring(1) : _folder;

			
			logger.info(String.format("Initialization Syncplicity connector Complete"));
			
			
			
		} catch (Exception e ) {
			throw new TransportInitializationException("Error getting settings", e);
		}
	}



	
	/**
	 * Create a session
	 */
	public void connect() throws UnableToConnectException {
		
		try {
			logger.info(String.format("Connecting to Syncplicity Server"));
			
		} catch (Exception e) {
			throw new UnableToConnectException("Unable to connect to Syncplity server");
		}
		
	}

	public void authenticate() throws UnableToAuthenticateException {
		
		try { 

			disableSslVerification();
			
			logger.info(String.format("Authenticating"));
			APIGateway.setOAuthParameters(OathParam);

			OAuth.authenticate();
			
			if( !APIContext.isAuthenticated() ) {
				logger.error( "The OAuth authentication has failed, cannot continue." );
				System.exit(1);
			}
			else {
				logger.info( "Authentication was successful." );			
			}
		} catch (Exception e) {
			throw new UnableToAuthenticateException("Unable to authenticate to Syncplity server");
		}

				

	}
	
	/**
	 * The Syncplicity interface is pollable. The isPollable
	 * method must return 'true' to tell the TE to call the 'list' method
	 */
	
	@Override
	public boolean isPollable() {
		boolean isPollable = true;
		logger.debug("isPollable returning: " + isPollable);
		return isPollable;
	}


	/**
	 * Send the message 
	 *
	 * @param message the message being processed by B2Bi
	 * @param returnMessage not used in this example
	 * @return always null
	 * @throws UnableToProduceException if there was a problem producing the message
	 */
	public PluggableMessage produce(PluggableMessage message, PluggableMessage returnMessage) throws UnableToProduceException {
		
		
		try { 
			
			logger.info(String.format("Producing message"));

			uploadFile(message, _folder);
		 	message.setMetadata("SyncplicityDeliveryFolder", _folder);
		 	

	     
		} catch (Exception e) {
		     logger.info("Error" + e);
			
		}     
		
		return null;
	}

	
	public PluggableMessage consume(PluggableMessage message, String idFromList) throws UnableToConsumeException, FileNotFoundException {
		

		try {

			SyncPoint ConsumptionSyncPoint = getStorageEndpoint(getEndpoint(_folder));

	        if (ConsumptionSyncPoint == null) {
	            logger.error("The syncpoint was not created at previous steps. No files will be retrieved.");
	            return null;
	        }

	        
	        // Get the Folder ID
	        
        	String FolderID = getFolderID(ConsumptionSyncPoint, _folder);
			
        	// Get Folder contents

        	logger.info("Now retrieving requested file(s) from folder: " + _folder);
					
		    Folder listfolder = FolderService.getFolder(ConsumptionSyncPoint.Id, FolderID, true);
	        logger.info("Number of files in the folder: " + listfolder.Files.length); 

	        
	        
	        File[] files = listfolder.Files;
	        if (files.length == 0) {
	            logger.info("No files in the syncpoint.");
	            return null;
	        } 
	        
	        for (int i = 0; i < files.length; i++) {
	        	if (files[i].FileId.equals(idFromList)) {

	        		// Download file 

	        		String fileId = files[i].FileId;
	    	        String downloadedFile = FileService.downloadFile(ConsumptionSyncPoint.Id, fileId, true);

	    	        // Attach file content
	    	        
	    	        InputStream targetStream = new ByteArrayInputStream(downloadedFile.getBytes());
				    VirtualData data = new VirtualData();
				    data.readFrom(targetStream);
				 	message.setData(data);
				 	message.setFilename(files[i].Filename);
				 	message.setMetadata("SyncplicityPickupFolder", _folder);
				 	message.setMetadata("SyncplicityFileName", files[i].Filename);
				 	message.setMetadata("SyncplicityFileCreationDate", files[i].CreationTimeUtc);
				 	message.setMetadata("SyncplicityFileLastModificationDate", files[i].LastWriteTimeUtc);
				 	//message.setMetadata("SyncplicityFileLatestVersion", String.valueOf(files[i].Versions[files[i].LatestVersionId].Id));
				
				 	
				 	// Delete the file if necessary
				 	if (_deleteAfterConsumption.equals("true")) {
					 	String something = FileService.deleteFile(ConsumptionSyncPoint.Id, fileId, true);
					 	logger.info("Delete status: " + something);
				 	
				 	}
				 	
				 	
	        	}
			}


		} catch (Exception e) {
	     logger.info("Error" + e);
		
		}     
		
	return message;	  
	

	}
	public static String getEndpoint(String Path) {

	   String splitFolderPath[] = Path.split("/");
	   
       if(splitFolderPath.length < 1) {
       	return null;
       } else {
    	   return splitFolderPath[0];
       }
	}
	
	
	public static String getFolderID (SyncPoint ConsumptionSyncPoint, String FolderName) {
	
	    String DownloadFolder = FolderName;
		String FolderID = "";
	    
	    String splitFolderPath[] = FolderName.split("/");    	
		
		
	    if(splitFolderPath.length < 2) {
	    	
	    	// Folder path must be EndpointPath
	    	FolderID = ConsumptionSyncPoint.RootFolderId;
	    	
	    } else {
	        logger.info("Path is a combination of endpoint and subfolders.");
	        
	        // Remove Syncpoint from provided folder path
	        
	        DownloadFolder = NonSyncPointPath(FolderName);
	
		    // Shortcut to get the download folder
	
	        Folder folder = new Folder();
	        folder.Name = DownloadFolder;
	        folder.Status = FolderStatus.Added;
	        Folder[] folders = { folder };
	        Folder[] createdFolders = FolderService.createFolders(ConsumptionSyncPoint.Id, ConsumptionSyncPoint.RootFolderId,
	                folders);
	        if (createdFolders == null || createdFolders.length == 0) {
	            logger.error("No folder was created.");
	            return null;
	        }
	        
	    	FolderID = createdFolders[0].FolderId;
	    }
	    
	    return FolderID;	
	}
	
	@Override
	public String getUrl() throws PluggableException {
		String _URL;
		_URL = "https://api.syncplicity.com ["+ _folder + "]";
		return _URL;
	}

	
	
	/**
	 * Return a list of files waiting in our consumption directory.  The trading engine will subsequently call
	 * consume once for each file in the list.  Since we could be running in a cluster of multiple trading
	 * engine nodes, we cannot say for sure whether consume will be called on the same machine as list was.
	 * Thus, the files need to be on a shared directory accessible from all the nodes in the cluster.
	 */
	public String[] list() throws UnableToConsumeException {
		
        logger.info("Retrieving the files from folder.");
    	String[] list = null;
	
		SyncPoint ListSyncPoint = getStorageEndpoint(getEndpoint(_folder));

        if (ListSyncPoint == null) {
            logger.info("No Syncpoint was found. No files will be retrieved.");
            return null;
        }
	        
	    // Get the Folder ID
	        
    	String FolderID = getFolderID(ListSyncPoint, _folder);
       	
		// Get the Folder Contents
        
        Folder folder = FolderService.getFolder(ListSyncPoint.Id, FolderID, true);
        File[] files = folder.Files;
        if (files.length == 0) {
            logger.info("No files in: " + _folder);
            return null;
        } 
        
        ArrayList<String> result = new ArrayList<String>();
        
        for (int i = 0; i < files.length; i++) {
        	
        	PatternKeyValidator validator = PatternKeyValidatorFactory.createPatternValidator(_filtertype);
        	if (validator.isValid(files[i].Filename, _filter)) {
        		result.add(files[i].FileId);
        	}
        	else {
        		logger.info(files[i].Filename + " does not match the defined filter (" + _filter +") and /or filter type (" + _filtertype + ")"); 
        	}
		
		}

		list = new String[result.size()];
		for (int i = 0; i < result.size(); i++) {
			list[i] = result.get(i);
			logger.info("Adding Item [" + i + "]: " + list[i]);
		}
        
        
        return list;
 
	}

	

	/**
	 * Delete the specified file in the consumption directory.  The trading engine will call this method after
	 * it has successfully called our consume method for this file.
	 *
	 * @param nameFromList the file reference to delete
	 */
	public void delete(String nameFromList) throws UnableToDeleteException, FileNotFoundException {
		
		
		
		
		
		
	}

	/**
	 * Return an information string if the Pluggable Transport is able to connect to the server.  
	 * Otherwise throw TransportTestException with an appropriate message.
	 */
	public String test() throws TransportTestException {
		
		try {
			
			disableSslVerification();
			OAuth.authenticate();

		} catch(Exception e) {
			return "Failed to connect to Syncplicity";
		}
		return "Success, connected to Syncplicity";
	}

	/**
	 * Disconnect
	 */
	public void disconnect() throws UnableToDisconnectException {
		logger.debug("Disconnecting from Syncplicity server");
		try {
		
		} catch(Exception e) {
			logger.error("Failed to disconnect from Syncplicity server");
		}
	}

	// Syncplicity 

    private static String NonSyncPointPath (String FullPath) {

        String splitFolderPath[] = FullPath.split("/");    	
        
    	final Path fullPath = Paths.get(FullPath);
    	final Path basePath = Paths.get(splitFolderPath[0]);
    	final Path relativePath = basePath.relativize(fullPath);

    	logger.info("Relative Path: "+ relativePath);
    	
    	return relativePath.toString().replace('\\', '/');
    }
	
	
    private static SyncPoint getStorageEndpoint(String FolderName) {
        SyncPoint[] syncPoints = SyncPointService.getSyncPoints(true);
        for (int i = 0; i < syncPoints.length; i++) {
			if (syncPoints[i].Name.equals(FolderName)) {
		        logger.info("Retrieved requested endpoint.");
				return syncPoints[i];
			}
        }
        logger.error("Failed to retrieved storage endpoint.");
        return null;
    }
    
   	
 	private static void uploadFile(PluggableMessage message, String uFolderName) {
         logger.info("Starting File upload..");

		SyncPoint ProductionSyncPoint = getStorageEndpoint(getEndpoint(uFolderName));
        
		StorageEndpoint[] storageEndpoints = StorageEndpointService.getStorageEndpoints(true);
		          
		StorageEndpoint storageEndpoint = null;
		  for (StorageEndpoint endpoint : storageEndpoints) {
		  	logger.info("Syncpoint Name: " + ProductionSyncPoint.Name);
		  	if (endpoint.Id.equals(ProductionSyncPoint.StorageEndpointId)) {
		          storageEndpoint = endpoint;
		    }
		}
          
           
  		logger.info("ProductionSyncPoint.Id: " + ProductionSyncPoint.Id);
        logger.info("ProductionSyncPoint Name: " + ProductionSyncPoint.Name);


          String UploadFolder = "";
          
          // Do some work to hash out the right folder
          String FolderID = getFolderID(ProductionSyncPoint, uFolderName);
          Folder ufolder = FolderService.getFolder(ProductionSyncPoint.Id, FolderID, true);
                   
          logger.info(String.format("Finished Folder creation. New Folder id: %s", FolderID));
           
          logger.info("Starting File upload..");
          byte[] fileBody = "file body".getBytes();
          String fileName = message.getMetadata(MetadataDictionary.CONSUMPTION_FILENAME);

                    
          String result = FileService.uploadFile(storageEndpoint.Urls[0].Url, ufolder.VirtualPath, fileName, ufolder.SyncpointId, fileBody);
          logger.info(String.format("Finished File upload. File upload result: %s", result));
		
		
	}
	

	private static void disableSslVerification() {
		try {
			// Create a trust manager that does not validate certificate chains
			TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
				public void checkClientTrusted(X509Certificate[] certs, String authType) { }
				public void checkServerTrusted(X509Certificate[] certs, String authType) { }

				public java.security.cert.X509Certificate[] getAcceptedIssuers() {
					return null;
				}
			}};
			// Install the all-trusting trust manager
			SSLContext sc = SSLContext.getInstance("SSL");
			sc.init(null, trustAllCerts, new java.security.SecureRandom());
			HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

			// Create all-trusting host name verifier
			HostnameVerifier allHostsValid = new HostnameVerifier() {
				@Override
				public boolean verify(String hostname, SSLSession session) {
					return true;
				}
			};
			// Install the all-trusting host verifier
			HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (KeyManagementException e) {
			e.printStackTrace();
		}
	}
	
	  	
}
