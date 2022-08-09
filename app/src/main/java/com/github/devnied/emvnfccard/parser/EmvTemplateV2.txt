/*
 * Copyright (C) 2019 MILLAU Julien
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.github.devnied.emvnfccard.parser;

import com.github.devnied.emvnfccard.enums.CommandEnum;
import com.github.devnied.emvnfccard.enums.EmvCardScheme;
import com.github.devnied.emvnfccard.enums.SwEnum;
import com.github.devnied.emvnfccard.exception.CommunicationException;
import com.github.devnied.emvnfccard.iso7816emv.EmvTags;
import com.github.devnied.emvnfccard.iso7816emv.ITerminal;
import com.github.devnied.emvnfccard.iso7816emv.TLV;
import com.github.devnied.emvnfccard.iso7816emv.TagAndLength;
import com.github.devnied.emvnfccard.iso7816emv.impl.DefaultTerminalImpl;
import com.github.devnied.emvnfccard.model.Afl;
import com.github.devnied.emvnfccard.model.Application;
import com.github.devnied.emvnfccard.model.EmvCard;
import de.androidcrypto.nfcemvccreaderdevnied.model.EmvCardAnalyze;

import com.github.devnied.emvnfccard.model.enums.ApplicationStepEnum;
import com.github.devnied.emvnfccard.model.enums.CardStateEnum;
import com.github.devnied.emvnfccard.parser.impl.EmvParser;
import com.github.devnied.emvnfccard.parser.impl.ProviderWrapper;
import com.github.devnied.emvnfccard.utils.CPLCUtils;
import com.github.devnied.emvnfccard.utils.CommandApdu;
import com.github.devnied.emvnfccard.utils.ResponseUtils;
import com.github.devnied.emvnfccard.utils.TlvUtil;
import com.github.devnied.emvnfccard.utils.TrackUtils;

import org.apache.commons.lang3.ArrayUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import fr.devnied.bitlib.BytesUtils;

/**
 * Emv Template.<br>
 * Class used to detect the EMV template of the card and select the right parser
 *
 * @author MILLAU Julien
 *
 */
public class EmvTemplate {

	/**
	 * Class Logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(EmvTemplate.class);

	/**
	 * Max record for SFI
	 */
	public static final int MAX_RECORD_SFI = 16;

	/**
	 * PPSE directory "2PAY.SYS.DDF01"
	 */
	private static final byte[] PPSE = "2PAY.SYS.DDF01".getBytes();

	/**
	 * PSE directory "1PAY.SYS.DDF01"
	 */
	private static final byte[] PSE = "1PAY.SYS.DDF01".getBytes();

	/**
	 * EMV Terminal
	 */
	private ITerminal terminal;

	/**
	 * Provider
	 */
	private IProvider provider;

	/**
	 * Parser list
	 */
	private List<IParser> parsers;

	/**
	 * Config
	 */
	private Config config;

	/**
	 * Card data
	 */
	private EmvCard card;

	/**
	 * Card data analyzing
	 */
	private EmvCardAnalyze emvCardAnalyze;

	public EmvCardAnalyze getEmvCardAnalyze() {
		return emvCardAnalyze;
	}

	/**
	 * Create builder
	 *
	 * @return a new instance of builder
	 */
	public static Builder Builder() {
		return new Builder();
	}

	/**
	 * Create a new Config
	 *
	 * @return a new instance of config
	 */
	public static Config Config() {
		return new Config();
	}

	/**
	 * Build a new Config.
	 */
	public static class Config {

		/**
		 * use contact less mode
		 */
		public boolean contactLess = true;

		/**
		 * Boolean to indicate if the parser need to read transaction history
		 */
		public boolean readTransactions = true;

		/**
		 * Boolean used to indicate if you want to read all card aids
		 */
		public boolean readAllAids = true;

		/**
		 * Boolean used to indicate if you want to extract ATS or ATR
		 */
		public boolean readAt = true;

		/**
		 * Boolean used to indicate if you want to read CPLC data
		 */
		public boolean readCplc = false;
		//public boolean readCplc = true;

		/**
		 * Boolean used to indicate to not add provided parser implementation
		 */
		public boolean removeDefaultParsers;

		/**
		 * Package private. Use {@link #Builder()} to build a new one
		 *
		 */
		Config() {
		}

		/**
		 * Setter for the field contactLess (default true)
		 *
		 * @param contactLess
		 *            the contactLess to set
		 * @return the config instance
		 */
		public Config setContactLess(final boolean contactLess) {
			this.contactLess = contactLess;
			return this;
		}

		/**
		 * Setter for the field readTransactions (default true)
		 *
		 * @param readTransactions
		 *            the readTransactions to set
		 * @return the config instance
		 */
		public Config setReadTransactions(final boolean readTransactions) {
			this.readTransactions = readTransactions;
			return this;
		}

		/**
		 * Setter for the field readAllAids (default true)
		 *
		 * @param readAllAids
		 *            the readAllAids to set
		 * @return the config instance
		 */
		public Config setReadAllAids(final boolean readAllAids) {
			this.readAllAids = readAllAids;
			return this;
		}

		/**
		 * Setter for the field removeDefaultParsers (default false)
		 *
		 * @param removeDefaultParsers
		 *            the removeDefaultParsers to set
		 * @return the config instance
		 */
		public Config setRemoveDefaultParsers(boolean removeDefaultParsers) {
			this.removeDefaultParsers = removeDefaultParsers;
			return this;
		}

		/**
		 * Setter for the field readAt (default true)
		 *
		 * @param readAt
		 *            the readAt to set
		 * @return the config instance
		 */
		public Config setReadAt(boolean readAt) {
			this.readAt = readAt;
			return this;
		}

		/**
		 * Setter for the field readCplc (default true)
		 *
		 * @param readCplc
		 *            the readCplc to set
		 * @return the config instance
		 */
		public Config setReadCplc(boolean readCplc) {
			this.readCplc = readCplc;
			return this;
		}

	}

	/**
	 * Build a new {@link EmvTemplate}.
	 * <p>
	 * Calling {@link #setProvider} is required before calling {@link #build()}.
	 * All other methods are optional.
	 */
	public static class Builder {

		private IProvider provider;
		private ITerminal terminal;
		private Config config;

		/**
		 * Package private. Use {@link #Builder()} to build a new one
		 *
		 */
		Builder() {
		}

		/**
		 * Setter for the field provider
		 *
		 * @param provider
		 *            the provider to set
		 * @return the config instance
		 */
		public Builder setProvider(final IProvider provider) {
			this.provider = provider;
			return this;
		}

		/**
		 * Setter for the field terminal
		 *
		 * @param terminal
		 *            the terminal to set
		 * @return the config instance
		 */
		public Builder setTerminal(final ITerminal terminal) {
			this.terminal = terminal;
			return this;
		}

		/**
		 * Setter for the field config
		 *
		 * @param config
		 *            the config to set
		 * @return the config instance
		 */
		public Builder setConfig(Config config) {
			this.config = config;
			return this;
		}

		EmvCardAnalyze emvCardAnalyze;

		/** Create the {@link EmvTemplate} instances. */
		public EmvTemplate build() {
			if (provider == null) {
				throw new IllegalArgumentException("Provider may not be null.");
			}
			// Set default terminal implementation
			if (terminal == null) {
				terminal = new DefaultTerminalImpl();
			}
			return new EmvTemplate(provider, terminal, config);
		}

	}

	/**
	 * Call {@link EmvParser} to create an new instance
	 *
	 * @param pProvider
	 *            provider to launch command and communicate with the card
	 * @param pTerminal
	 *            terminal data
	 * @param pConfig
	 *            parser configuration (Default configuration used if null)
	 */
	private EmvTemplate(final IProvider pProvider, final ITerminal pTerminal, final Config pConfig) {
		provider = new ProviderWrapper(pProvider);
		terminal = pTerminal;
		config = pConfig;
		if (config == null) {
			config = Config();
		}
		// new
		emvCardAnalyze = new EmvCardAnalyze();

		parsers = new ArrayList<IParser>();
		if (!config.removeDefaultParsers) {
			addDefaultParsers();
		}
		card = new EmvCard();

	}

	/**
	 * Add default parser implementation
	 */
	private void addDefaultParsers() {
		//parsers.add(new GeldKarteParser(this));
		//parsers.add(new EmvParser(this));
		parsers.add(new EmvParser(this, emvCardAnalyze));
	}

	/**
	 * Method used to add a list of parser to the current EMV template
	 *
	 * @param pParsers
	 *            parser implementation to add
	 * @return current EmvTemplate
	 */
	public EmvTemplate addParsers(final IParser... pParsers) {
		if (pParsers != null) {
			for (IParser parser : pParsers) {
				parsers.add(0, parser);
			}
		}
		return this;
	}

	/**
	 *
	 * Section for single tasks start
	 */

	/**
	 * Read EMV card with Payment System Environment or Proximity Payment System
	 * Environment
	 *
	 * @return true is succeed false otherwise
	 * @throws CommunicationException communication error
	 */
	public byte[] selectPpse() throws CommunicationException {
		System.out.println("#*# selectPpse");
		byte[] apduSelectPpseCommand = new CommandApdu(CommandEnum.SELECT, PPSE, 0).toBytes();
		emvCardAnalyze.setApduSelectPpseCommand(apduSelectPpseCommand);
		byte[] apduSelectPpseResponse = provider.transceive(apduSelectPpseCommand);
		System.out.println("#*# apduSelectPpseCommand: " + BytesUtils.bytesToString(apduSelectPpseCommand));
		System.out.println("#*# apduSelectPpseResponse: " + BytesUtils.bytesToString(apduSelectPpseResponse));
		emvCardAnalyze.setApduSelectPpseResponse(apduSelectPpseResponse);
		return apduSelectPpseResponse;
	}

	public List<byte[]> getAidsFromPpseResponse(byte[] ppseResponse) throws CommunicationException {
		System.out.println("#*# get AIDs from ppseResponse: " + BytesUtils.bytesToString(ppseResponse));
		if (ResponseUtils.isSucceed(ppseResponse)) {
			List<byte[]> aidsList = new ArrayList<byte[]>();
			List<TLV> tlvList = TlvUtil.getlistTLV(ppseResponse, EmvTags.AID_CARD);
			aidsList.clear();
			int tlvListSize = tlvList.size();
			for (int i = 0; i < tlvListSize; i++) {
				System.out.println("i: " + BytesUtils.bytesToString(tlvList.get(i).getTagBytes()) + " value: " + BytesUtils.bytesToString(tlvList.get(i).getValueBytes()));
				aidsList.add(tlvList.get(i).getValueBytes());
			}
			emvCardAnalyze.setAidsList(aidsList);
			return aidsList;
		} else {
			System.out.println("#*# ppseResponse is not successfull");
			return null;
		}
	}


	/**
	 * Read EMV card with Payment System Environment or Proximity Payment System
	 * Environment
	 *
	 * @return true is succeed false otherwise
	 * @throws CommunicationException communication error
	 */
	public byte[] selectPid(byte[] aidByte) throws CommunicationException {
		System.out.println("#*# selectPid with AID: " + BytesUtils.bytesToString(aidByte));
		// todo null or empty check
		byte[] apduSelectPidCommand = new CommandApdu(CommandEnum.SELECT, aidByte, 0).toBytes();
		// todo use List<byte[]> getApduSelectPidCommands()
		emvCardAnalyze.setApduSelectPidCommand(apduSelectPidCommand);
		byte[] apduSelectPidResponse = provider.transceive(apduSelectPidCommand);
		System.out.println("#*# apduSelectPidCommand: " + BytesUtils.bytesToString(apduSelectPidCommand));
		System.out.println("#*# apduSelectPidResponse: " + BytesUtils.bytesToString(apduSelectPidResponse));
		// todo use List<byte[]> getApduSelectPidResponses()
		emvCardAnalyze.setApduSelectPidResponse(apduSelectPidResponse);
		return apduSelectPidResponse;

		/*
		if (ResponseUtils.isSucceed(apduSelectPidResponse)) {



			// Parse FCI Template
			// step 2 parse the File Control Information (FCI) Template
			List<Application> fciProprietaryTemplateList = parseFCIProprietaryTemplate(data);
			emvCardAnalyze.setFciProprietaryTemplateList(fciProprietaryTemplateList);

			card.getApplications().addAll(parseFCIProprietaryTemplate(data));
			Collections.sort(card.getApplications());
			// For each application
			for (Application app : card.getApplications()) {
				boolean status = false;
				String applicationAid = BytesUtils.bytesToStringNoSpace(app.getAid());
				for (IParser impl : parsers) {
					if (impl.getId() != null && impl.getId().matcher(applicationAid).matches()) {
						status = impl.parse(app);
						break;
					}
				}
				if (!ret && status) {
					ret = status;
					if (!config.readAllAids) {
						break;
					}
				}
			}
			if (!ret) {
				card.setState(CardStateEnum.LOCKED);
			}
		} else if (LOGGER.isDebugEnabled()) {
			LOGGER.debug((config.contactLess ? "PPSE" : "PSE") + " not found -> Use kown AID");
		}

		return ret;

		 */
	}





	// this method is copied and adopted from EmvParser.java
	/**
	 * Method used to parse EMV card
	 *
	 * @param pSelectResponse
	 *            select response data
	 * @return true if the parsing succeed false otherwise
	 * @throws CommunicationException communication error
	 */
	public byte[] parseSelectResponse(final byte[] pSelectResponse) throws CommunicationException {
		System.out.println("#*# parse with SelectResponse: " + BytesUtils.bytesToString(pSelectResponse));
		boolean ret = false;
		// Get TLV log entry
		//byte[] logEntry = getLogEntry(pSelectResponse);
		// Get PDOL
		byte[] pdol = TlvUtil.getValue(pSelectResponse, EmvTags.PDOL);
		System.out.println("#*# parse pdol: " + BytesUtils.bytesToString(pdol));
		// Send GPO Command
		byte[] gpo = getGetProcessingOptions(pdol);
		System.out.println("#*# parse gpo 1.st: " + BytesUtils.bytesToString(gpo));
		// Extract Bank data
		//extractBankData(pSelectResponse);

		// DKB Visa cards makes some problems, seems to be a wrong GPO because the card responses 69 84
		if (ResponseUtils.contains(gpo, SwEnum.SW_6984)) {
			System.out.println("#*# parse gpo 1.st failed with response: 69 84, trying another PDOL");
			String pdolWithoutCountryCode = "80A8000023832180000000000000000000000000000000000000000000000000000000000000000000";
			String pdolWithCountryCode = "80A80000238321A0000000000000000001000000000000084000000000000840070203008017337000";
			//byte[] pdolNew = BytesUtils.fromString(pdolWithoutCountryCode);
			byte[] pdolNew = BytesUtils.fromString(pdolWithCountryCode);
			System.out.println("#*# parse with pdolNew: " + BytesUtils.bytesToString(pdolNew));
			gpo = provider.transceive(pdolNew);
			System.out.println("#*# parse with pdolNew gpo: " + BytesUtils.bytesToString(gpo));
		}

		// Check empty PDOL
		if (!ResponseUtils.isSucceed(gpo)) {
			if (pdol != null) {
				gpo = getGetProcessingOptions(null);
				System.out.println("#*# parse pdol != null gpo 2.nd: " + BytesUtils.bytesToString(gpo));
			}

			// Check response
			if (pdol == null || !ResponseUtils.isSucceed(gpo)) {
				// Try to read EF 1 and record 1
				//gpo = template.get().getProvider().transceive(new CommandApdu(CommandEnum.READ_RECORD, 1, 0x0C, 0).toBytes());
				gpo = provider.transceive(new CommandApdu(CommandEnum.READ_RECORD, 1, 0x0C, 0).toBytes());
				System.out.println("#*# parse pdol == null gpo 3.rd: " + BytesUtils.bytesToString(gpo));
				if (!ResponseUtils.isSucceed(gpo)) {
					//return false;
					return null;
				}
			}
		}
		// Update Reading state
		//pApplication.setReadingStep(ApplicationStepEnum.READ);
/*
		// Extract commons card data (number, expire date, ...)
		if (extractCommonsCardData(gpo)) {
			// Extract log entry
			pApplication.setListTransactions(extractLogEntry(logEntry));
			ret = true;
		}
*/
		System.out.println("#*# parse with SelectResponse gpo: " + BytesUtils.bytesToString(gpo));
		return gpo;
	}

	// works with DKB Visa debit card and other Visa cards
	public byte[] parseSelectResponseVisa() throws CommunicationException {
		System.out.println("#*# parse selectResponseVisa: ");
		System.out.println("#*# parse gpo 1.st failed with response: 69 84, trying another PDOL");
		String pdolWithoutCountryCode = "80A8000023832180000000000000000000000000000000000000000000000000000000000000000000";
		String pdolWithCountryCode = "80A80000238321A0000000000000000001000000000000084000000000000840070203008017337000";
		// byte[] pdolNew = BytesUtils.fromString(pdolWithoutCountryCode); // does not work
		byte[] pdolNew = BytesUtils.fromString(pdolWithCountryCode);
		System.out.println("#*# parse with pdolNew: " + BytesUtils.bytesToString(pdolNew));
		byte[] gpo;
		gpo = provider.transceive(pdolNew);
		System.out.println("#*# parse with pdolNew gpo: " + BytesUtils.bytesToString(gpo));
		return gpo;
	}


	// this method is copied and adopted from EmvParser.java
	/**
	 * Method used to create GPO command and execute it
	 *
	 * @param pPdol
	 *            PDOL raw data
	 * @return return data
	 * @throws CommunicationException communication error
	 */
	protected byte[] getGetProcessingOptions(final byte[] pPdol) throws CommunicationException {
		System.out.println("#*# getGetProcessingOptions with pdol: " + BytesUtils.bytesToString(pPdol));
		// List Tag and length from PDOL
		List<TagAndLength> list = TlvUtil.parseTagAndLength(pPdol);
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try {
			out.write(EmvTags.COMMAND_TEMPLATE.getTagBytes()); // COMMAND
			// TEMPLATE
			out.write(TlvUtil.getLength(list)); // ADD total length
			if (list != null) {
				for (TagAndLength tl : list) {
					//out.write(template.get().getTerminal().constructValue(tl));
					DefaultTerminalImpl defaultTerminal = new DefaultTerminalImpl();
					out.write(defaultTerminal.constructValue(tl));
				}
			}
		} catch (IOException ioe) {
			LOGGER.error("Construct GPO Command:" + ioe.getMessage(), ioe);
		}
		byte[] apduGetProcessingOptionsCommand = new CommandApdu(CommandEnum.GPO, out.toByteArray(), 0).toBytes();
		System.out.println("#*# getGetProcessingOptionsCommand: " + BytesUtils.bytesToString(apduGetProcessingOptionsCommand));
		byte[] apduGetProcessingOptionsResponse = provider.transceive(apduGetProcessingOptionsCommand);
		// todo store in emvCardAnalyze
		//emvCardAnalyze.setApduGetProcessingOptionsCommand(apduGetProcessingOptionsCommand);
		//emvCardAnalyze.setApduGetProcessingOptionsResponse(apduGetProcessingOptionsResponse);
		return apduGetProcessingOptionsResponse;
		//return template.get().getProvider().transceive(new CommandApdu(CommandEnum.GPO, out.toByteArray(), 0).toBytes());
	}
	// DKB V: getGetProcessingOptionsCommand: 80 A8 00 00 23 83 21 F6 20 C0 00 00 00 00 00 00 01 00 00 00 00 00 00 02 50 00 00 00 00 00 09 78 22 08 08 00 33 A2 3B 6B 00
	// sample without country code:           80 A8 00 00 23 83 21 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	// sample with country code:              80 A8 00 00 23 83 21 A0 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 08 40 00 00 00 00 00 08 40 07 02 03 00 80 17 33 70 00
	// data from https://stackoverflow.com/a/24964964/8166854
	// sample without country code: 80A8000023832180000000000000000000000000000000000000000000000000000000000000000000
	// sample with country code:    80A80000238321A0000000000000000001000000000000084000000000000840070203008017337000

	public byte[] getGpoForVisaCards() {
		System.out.println("#*# getGpoForVisa (complete run)");
		try {
			byte[] selectPpseResponse = selectPpse();
			List<byte[]> aidsList = getAidsFromPpseResponse(selectPpseResponse);
			// we are using just the first aid
			byte[] selectedAid = aidsList.get(0);
			byte[] selectPidResponse = selectPid(selectedAid);
			byte[] gpoVisa = parseSelectResponseVisa();
			return gpoVisa;
		} catch (CommunicationException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Method used to parse FCI Proprietary Template
	 *
	 * @param pData
	 *            data to parse
	 * @return the list of EMV application in the card
	 * @throws CommunicationException communication error
	 */
	public List<Application> parseGpo(final byte[] pData) throws CommunicationException {
		// todo remove debug print
		//System.out.println("*#* parseFCIProprietaryTemplate started");
		System.out.println("*#* parseGpo started");
		List<Application> ret = new ArrayList<Application>();
		// Get SFI
		byte[] data = TlvUtil.getValue(pData, EmvTags.SFI);

		// Check SFI
		if (data != null) {
			int sfi = BytesUtils.byteArrayToInt(data);
			System.out.println("*#* parseGpo: SFI: " + sfi);
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("SFI found:" + sfi);
			}
			// todo remove #*# debug print
			System.out.println("*#* Check SFI is not null, parsing the data *#*");
			// For each records
			for (int rec = 0; rec < MAX_RECORD_SFI; rec++) {
				// todo remove #*# debug print
				System.out.println("*#* rec: " + rec + " sfi: " + sfi + " sfi << 3 | 4: " + (sfi << 3 | 4));
				byte[] sfiCommand = new CommandApdu(CommandEnum.READ_RECORD, rec, sfi << 3 | 4, 0).toBytes();
				data = provider.transceive(sfiCommand);
				System.out.println("*#* sfi command : " + BytesUtils.toBinary(sfiCommand));
				System.out.println("*#* sfi response: " + BytesUtils.toBinary(data));
				// Check response
				if (ResponseUtils.isSucceed(data)) {
					// Get applications Tags
					//ret.addAll(getApplicationTemplate(data));
				} else {
					// No more records
					break;
				}
			}
		} else {
			// todo remove debug print
			System.out.println("*#* checkSFI = null");
			// Read Application template
			ret.addAll(getApplicationTemplate(pData));
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("(FCI) Issuer Discretionary Data is already present");
			}
		}
		return ret;
	}

	// this method is copied and adopted from EmvParser.java
	/**
	 * Method used to extract commons card data
	 *
	 * @param pGpo
	 *            global processing options response
	 * @return true if the extraction succeed
	 * @throws CommunicationException communication error
	 */
	public byte[] extractCommonsCardData(final byte[] pGpo) throws CommunicationException {
		System.out.println("*#* extractCommonsCardData started with gpo: " + BytesUtils.bytesToString(pGpo));
		boolean ret = false;
		// Extract data from Message Template 1
		System.out.println("*#* extractCommonsCardData try to find RESPONSE_MESSAGE_TEMPLATE_1");
		byte data[] = TlvUtil.getValue(pGpo, EmvTags.RESPONSE_MESSAGE_TEMPLATE_1);
		if (data != null) {
			System.out.println("*#* extractCommonsCardData try to find RESPONSE_MESSAGE_TEMPLATE_1 found");
			data = ArrayUtils.subarray(data, 2, data.length);
		} else { // Extract AFL data from Message template 2
			System.out.println("*#* extractCommonsCardData try to find RESPONSE_MESSAGE_TEMPLATE_2");
			ret = extractTrackData(card, pGpo);
			if (!ret) {
				data = TlvUtil.getValue(pGpo, EmvTags.APPLICATION_FILE_LOCATOR);
				System.out.println("*#* extractCommonsCardData APPLICATION_FILE_LOCATOR data: " + BytesUtils.bytesToString(data));
			} else {
				// todo anything else to read
				//extractCardHolderName(pGpo);
			}
		}

		if (data != null) {
			// Extract Afl
			System.out.println("*#* extractCommonsCardData extract AFL");
			List<Afl> listAfl = extractAfl(data);
			// for each AFL
			for (Afl afl : listAfl) {
				// check all records
				for (int index = afl.getFirstRecord(); index <= afl.getLastRecord(); index++) {
					byte[] apduReadRecordCommand = new CommandApdu(CommandEnum.READ_RECORD, index, afl.getSfi() << 3 | 4, 0).toBytes();
					//byte[] info = provider.transceive(apduReadRecordCommand);
					byte[] apduReadRecordResponse = provider.transceive(apduReadRecordCommand);
					System.out.println("#*# apduReadRecordCommand: " + BytesUtils.bytesToString(apduReadRecordCommand));
					System.out.println("#*# apduReadRecordResponse: " + BytesUtils.bytesToString(apduReadRecordResponse));

					// Extract card data
					if (ResponseUtils.isSucceed(apduReadRecordResponse)) {
						// todo is there anything else to read ?
						/*
						extractCardHolderName(info);
						if (extractTrackData(template.get().getCard(), info)) {
							return true;
						}*/
					}
				}
			}
		}
		return data;
		// on new Visa the card number PAN is in Tag 57
		// How to interpret the Data of 57 Tag in an Visa EMV transaction?
		// https://atlassian.idtechproducts.com/confluence/pages/viewpage.action?pageId=112891693

		//Skip to end of metadata
	}

	// this method is copied and adopted from EmvParser.java
	/**
	 * Extract list of application file locator from Afl response
	 *
	 * @param pAfl
	 *            AFL data
	 * @return list of AFL
	 */
	protected List<Afl> extractAfl(final byte[] pAfl) {
		List<Afl> list = new ArrayList<Afl>();
		ByteArrayInputStream bai = new ByteArrayInputStream(pAfl);
		while (bai.available() >= 4) {
			Afl afl = new Afl();
			afl.setSfi(bai.read() >> 3);
			afl.setFirstRecord(bai.read());
			afl.setLastRecord(bai.read());
			afl.setOfflineAuthentication(bai.read() == 1);
			list.add(afl);
		}
		return list;
	}

	// this method is copied and adopted from EmvParser.java
	/**
	 * Method used to extract track data from response
	 *
	 * @param pEmvCard
	 *            Card data
	 * @param pData
	 *            data send by card
	 * @return true if track 1 or track 2 can be read
	 */
	protected boolean extractTrackData(final EmvCard pEmvCard, final byte[] pData) {
		// todo should we read the data ?
		/*
		template.get().getCard().setTrack1(TrackUtils.extractTrack1Data(TlvUtil.getValue(pData, EmvTags.TRACK1_DATA)));
		template.get().getCard().setTrack2(TrackUtils.extractTrack2EquivalentData(TlvUtil.getValue(pData, EmvTags.TRACK_2_EQV_DATA, EmvTags.TRACK2_DATA)));
		return pEmvCard.getTrack1() != null || pEmvCard.getTrack2() != null;
		 */
		return false;
	}


	/**
	 *
	 * Section for single tasks end
	 */


	/**
	 * Method used to read public data from EMV card
	 *
	 * @return data read from card or null if any provider match the card type
	 * @throws CommunicationException communication error
	 */
	public EmvCard readEmvCard() throws CommunicationException {
		// Read CPLC Infos
		if (config.readCplc){
			readCPLCInfos();
		}

		// Update ATS or ATR
		if (config.readAt){
			// todo try to get AtrDescription from AtrUtils, here removed
			card.setAt(BytesUtils.bytesToStringNoSpace(provider.getAt()));
			// card.setAtrDescription(config.contactLess ? AtrUtils.getDescriptionFromAts(card.getAt()) : AtrUtils.getDescription(card.getAt()));
		}
		// use PSE first
		if (!readWithPSE()) {
			// Find with AID
			readWithAID();
		}

		return card;
	}

	/**
	 *
	 * Try to read generic infos about the SmartCard as defined in the
	 * "GlobalPlatform Card Specification" (GPCS).
	 * @throws CommunicationException communication error
	 *
	 */
	protected void readCPLCInfos() throws CommunicationException {
		card.setCplc(CPLCUtils.parse(provider.transceive(new CommandApdu(CommandEnum.GET_DATA, 0x9F, 0x7F, null, 0).toBytes())));
	}

	/**
	 * Read EMV card with Payment System Environment or Proximity Payment System
	 * Environment
	 *
	 * @return true is succeed false otherwise
	 * @throws CommunicationException communication error
	 */
	protected boolean readWithPSE() throws CommunicationException {
		boolean ret = false;
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("Try to read card with Payment System Environment");
		}
		// Select the payment environment PPSE or PSE directory
		byte[] data = selectPaymentEnvironment();
		// # step 1 store apduSelectPpseResponse in EmvCardAnalyze
		emvCardAnalyze.setApduSelectPpseResponse(data);
		if (ResponseUtils.isSucceed(data)) {
			// Parse FCI Template
			// step 2 parse the File Control Information (FCI) Template
			List<Application> fciProprietaryTemplateList = parseFCIProprietaryTemplate(data);
			emvCardAnalyze.setFciProprietaryTemplateList(fciProprietaryTemplateList);

			card.getApplications().addAll(parseFCIProprietaryTemplate(data));
			Collections.sort(card.getApplications());
			// For each application
			for (Application app : card.getApplications()) {
				boolean status = false;
				String applicationAid = BytesUtils.bytesToStringNoSpace(app.getAid());
				for (IParser impl : parsers) {
					if (impl.getId() != null && impl.getId().matcher(applicationAid).matches()) {
						status = impl.parse(app);
						break;
					}
				}
				if (!ret && status) {
					ret = status;
					if (!config.readAllAids) {
						break;
					}
				}
			}
			if (!ret) {
				card.setState(CardStateEnum.LOCKED);
			}
		} else if (LOGGER.isDebugEnabled()) {
			LOGGER.debug((config.contactLess ? "PPSE" : "PSE") + " not found -> Use kown AID");
		}

		return ret;
	}

	/**
	 * Method used to parse FCI Proprietary Template
	 *
	 * @param pData
	 *            data to parse
	 * @return the list of EMV application in the card
	 * @throws CommunicationException communication error
	 */
	protected List<Application> parseFCIProprietaryTemplate(final byte[] pData) throws CommunicationException {
		// todo remove debug print
		System.out.println("*#* parseFCIProprietaryTemplate started");
		List<Application> ret = new ArrayList<Application>();
		// Get SFI
		byte[] data = TlvUtil.getValue(pData, EmvTags.SFI);

		// Check SFI
		if (data != null) {
			int sfi = BytesUtils.byteArrayToInt(data);
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("SFI found:" + sfi);
			}
			// todo remove #*# debug print
			System.out.println("*#* Check SFI is not null, parsing the data *#*");
			// For each records
			for (int rec = 0; rec < MAX_RECORD_SFI; rec++) {
				// todo remove #*# debug print
				System.out.println("*#* rec: " + rec + " sfi: " + sfi + " sfi << 3 | 4: " + (sfi << 3 | 4));
				byte[] sfiCommand = new CommandApdu(CommandEnum.READ_RECORD, rec, sfi << 3 | 4, 0).toBytes();
				data = provider.transceive(new CommandApdu(CommandEnum.READ_RECORD, rec, sfi << 3 | 4, 0).toBytes());
				System.out.println("*#* sfi command : " + BytesUtils.toBinary(sfiCommand));
				System.out.println("*#* sfi response: " + BytesUtils.toBinary(data));
				// Check response
				if (ResponseUtils.isSucceed(data)) {
					// Get applications Tags
					ret.addAll(getApplicationTemplate(data));
				} else {
					// No more records
					break;
				}
			}
		} else {
			// todo remove debug print
			System.out.println("*#* checkSFI = null");
			// Read Application template
			ret.addAll(getApplicationTemplate(pData));
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("(FCI) Issuer Discretionary Data is already present");
			}
		}
		return ret;
	}

	/**
	 * Method used to get the application list, if the Kernel Identifier is
	 * defined, <br>
	 * this value need to be appended to the ADF Name in the data field of <br>
	 * the SELECT command.
	 *
	 * @param pData
	 *            FCI proprietary template data
	 * @return the application data (Aid,extended Aid, ...)
	 */
	protected List<Application> getApplicationTemplate(final byte[] pData) {
		// todo remove debug print
		System.out.println("*#* getApplicationTemplate started, data: " + BytesUtils.bytesToString(pData));
		List<Application> ret = new ArrayList<Application>();
		// Search Application template
		List<TLV> listTlv = TlvUtil.getlistTLV(pData, EmvTags.APPLICATION_TEMPLATE);
		// todo remove debug print
		System.out.println("*#* listTlv size: " + listTlv.size());
		// For each application template
		for (TLV tlv : listTlv) {
			// todo remove debug print
			System.out.println("*#* tlv tag: " + tlv.getTag() + " tlvValueBytes: " + BytesUtils.toBinary(tlv.getValueBytes()));
			Application application = new Application();
			// Get AID, Kernel_Identifier and application label
			List<TLV> listTlvData = TlvUtil.getlistTLV(tlv.getValueBytes(), EmvTags.AID_CARD, EmvTags.APPLICATION_LABEL,
					EmvTags.APPLICATION_PRIORITY_INDICATOR);
			// For each data
			for (TLV data : listTlvData) {
				if (data.getTag() == EmvTags.APPLICATION_PRIORITY_INDICATOR) {
					application.setPriority(BytesUtils.byteArrayToInt(data.getValueBytes()));
				} else if (data.getTag() == EmvTags.APPLICATION_LABEL) {
					application.setApplicationLabel(new String(data.getValueBytes()));
				} else {
					application.setAid(data.getValueBytes());
					ret.add(application);
				}
			}
		}
		return ret;
	}

	/**
	 * Read EMV card with AID
	 */
	protected void readWithAID() throws CommunicationException {
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("Try to read card with AID");
		}
		// Test each card from know EMV AID
		Application app = new Application();
		for (EmvCardScheme type : EmvCardScheme.values()) {
			for (byte[] aid : type.getAidByte()) {
				app.setAid(aid);
				app.setApplicationLabel(type.getName());
				String applicationAid = BytesUtils.bytesToStringNoSpace(aid);
				for (IParser impl : parsers) {
					if (impl.getId() != null && impl.getId().matcher(applicationAid).matches() && impl.parse(app)) {
						// Remove previously added Application template
						card.getApplications().clear();
						// Add Application
						card.getApplications().add(app);
						return;
					}
				}
			}
		}
	}

	/**
	 * Method used to select payment environment PSE or PPSE
	 *
	 * @return response byte array
	 * @throws CommunicationException communication error
	 */
	protected byte[] selectPaymentEnvironment() throws CommunicationException {
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("Select " + (config.contactLess ? "PPSE" : "PSE") + " Application");
		}
		// Select the PPSE or PSE directory
		// # step 01: Select the PPSE or PSE directory
		// log the command in EmvCardAnalyze
		byte[] apduSelectPpseCommand = new CommandApdu(CommandEnum.SELECT, config.contactLess ? PPSE : PSE, 0).toBytes();
		emvCardAnalyze.setApduSelectPpseCommand(apduSelectPpseCommand);
		return provider.transceive(apduSelectPpseCommand);
	}

	/**
	 * Method used to get the field card
	 *
	 * @return the card
	 */
	public EmvCard getCard() {
		return card;
	}

	/**
	 * Get the field provider
	 *
	 * @return the provider
	 */
	public IProvider getProvider() {
		return provider;
	}

	/**
	 * Get the field config
	 *
	 * @return the config
	 */
	public Config getConfig() {
		return config;
	}

	/**
	 * Get the field terminal
	 *
	 * @return the terminal
	 */
	public ITerminal getTerminal() {
		return terminal;
	}

	/**
	 * Get the field parsers
	 *
	 * @return the parsers
	 */
	public List<IParser> getParsers() {
		return Collections.unmodifiableList(parsers);
	}

}
