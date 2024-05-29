package fr.cacf.smartconnect.services;

import static java.util.Map.entry;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.transaction.Transactional;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response.Status;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import com.cacf.happy.shared.exception.HappyBusinessException;
import com.cacf.happy.shared.exception.HappyClientException;
import com.cacf.happy.shared.exception.HappyForbiddenException;
import com.cacf.happy.shared.exception.HappyValidationException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import fr.cacf.smartconnect.dtos.FrontalHabilitationDTO;
import fr.cacf.smartconnect.dtos.PartnerDTO;
import fr.cacf.smartconnect.dtos.SmartConnectHabilitationDTO;
import fr.cacf.smartconnect.dtos.UserDTO;
import fr.cacf.smartconnect.event.TraceErrorEvent;
import fr.cacf.smartconnect.event.exception.EventErrorTraceException;
import fr.cacf.smartconnect.model.EmailStateEnum;
import fr.cacf.smartconnect.model.EmailTrace;
import fr.cacf.smartconnect.model.Event;
import fr.cacf.smartconnect.model.Notification;
import fr.cacf.smartconnect.model.Request;
import fr.cacf.smartconnect.model.UniqueURL;
import fr.cacf.smartconnect.resourceclient.ldap.LdapResourceClient;
import fr.cacf.smartconnect.resourceclient.ldap.model.GroupLDAP;
import fr.cacf.smartconnect.resourceclient.ldap.model.UserLDAP;
import fr.cacf.smartconnect.security.Role;
import fr.cacf.smartconnect.security.SecurityServiceUtils;
import fr.cacf.smartconnect.services.mappers.GroupMapper;
import fr.cacf.smartconnect.services.mappers.UserMapper;
import fr.cacf.smartconnect.services.mappers.UtilsMapper;
import fr.cacf.smartconnect.utils.GroupUtils;
import fr.cacf.smartconnect.utils.UserUtils;
import lombok.extern.log4j.Log4j2;

@Service
@Log4j2
@Transactional(rollbackOn = HappyClientException.class, dontRollbackOn = { EventErrorTraceException.class })
public class UserService {

	private static final String LOAD_USER_MSG = "Load  Authenticated user {}";

	private static final String USER_JSON_ERROR_CODE = "USER_JSON_ERROR";
	private static final String EMAIL_ALREADY_EXIST_CODE = "EMAIL_ALREADY_EXIST";
	private static final String FORBIDDEN_CODE = "FORBIDDEN";
	private static final String USER_NOT_FOUND_CODE = "USERNOTFOUND";

	private static final String USER_JSON_ERROR_SHORTLIB = "An error has occurred during the serialization of the user's object";
	private static final String EMAIL_ALREADY_EXIST_SHORTLIB = "The mail's address has been already assigned to an existing user";

	private static final String SMARTCONNECT_LABEL = "SMARTCONNECT";
	private static final String CODEPA_LABEL = "codePA";
	private static final String CODEPARTNER_LABEL = "codePartner";
	private static final String COMPANY_LABEL = "company";
	private static final String EMAIL_LABEL = "email";
	private static final String FRONTAL_LABEL = "frontal";
	private static final String MANAGER_LABEL = "manager";
	private static final String PERSONALTITLE_LABEL = "personalTitle";
	private static final String POINTOFSALE_LABEL = "pointOfSale";
	private static final String USER_DTO = "userDTO";
	private static final String AUTH_USER_DTO = "authUserDTO";

	private static final String TR008 = "TR-008";
	private static final String REMOVE = "remove";

	private static final String CHECK_EMAIL_EXISTENCE = "check email existence {}";
	private static final String EMAIL_ALREADY_ASSIGNED = "mail's address already assigned to an existing user(s) {}";
	private static final String ERROR_OCCURED = "an error is occured during the verification ";
	private static final String SMARTCONNECT_HABILITATION_DTO = "smartConnectHabilitationDTO";
	private static final String FRONTAL_HABILITATION_DTO = "frontalHabilitationDTO";

	private static final String THE_USER = "The user ";
	private static final String CONCERNED = "concerned";
	private static final String GROUP_TYPE = "groupType";
	private static final String BAD_ID_PATERN = "BAD_ID_PATERN";
	private static final String BAD_CODEPATERN_PATERN_MSG = "The given id does not respect the correct patern (11 characters)";

	private static final String CODE_PIN = "code PIN";
	private static final String MOT_DE_PASSE = "mot de passe";

	private static final String LIMIT_LABEL = "limit";

	@Autowired
	private LdapResourceClient ldapResourceClient;

	@Autowired
	private EventService eventService;

	@Autowired
	private ConfigService configService;

	@Autowired
	private ApplicationEventPublisher applicationEventPublisher;

	@Autowired
	private SecurityServiceUtils securityServiceUtils;

	@Autowired
	private UserMapper userMapper;

	@Autowired
	private UtilsMapper utilsMapper;

	@Autowired
	private GroupMapper groupMapper;

	@Autowired
	private GroupUtils groupUtils;

	@Autowired
	private UserUtils userUtils;

	@Value("${regex.identifier}")
	public String regexIdentifier;

	@Value("${regex.email}")
	public String regexEmail;

	@Value("${server.front.url}")
	public String frontUrl;

	private static DateTimeFormatter dtf = DateTimeFormatter.ofPattern("dd/MM/yyyy à HH:mm:ss");
	private static DateTimeFormatter reviewDtf = DateTimeFormatter.ofPattern("dd/MM/yyyy");

	public boolean isUserCode(String value) {
		Pattern p = Pattern.compile(regexIdentifier);
		Matcher m = p.matcher(value);
		return m.matches();
	}

	public boolean isMailAddress(String value) {
		Pattern p = Pattern.compile(regexEmail);
		Matcher m = p.matcher(value);
		return m.matches();
	}

	String generateUniqueURL(UniqueURL uniqueURL) {
		return frontUrl + uniqueURL.getContext() + "/" + uniqueURL.getToken();
	}

	public UserDTO createVendorUserByResponsable(UserDTO userDTO) {

		UserDTO authUser = this.securityServiceUtils.loadAuthenticatedUserFromContext();
		if (Role.ADMIN == authUser.getRole() || Role.FORMATEUR == authUser.getRole() || Role.GESTIONNAIRE == authUser.getRole()) {
			return this.createVendorUser(userDTO);
		} else {
			throw new HappyClientException(Status.FORBIDDEN, "USER_AUTH_FORBIDDEN",
					"The user [" + authUser.getCodePA() + "] didn't have the authority to execute this action");
		}
	}

	public PartnerDTO preparePartnerForInitialization(String codePartner/* , String codeSIREN */) {

		UserDTO authUser = this.securityServiceUtils.loadAuthenticatedUserFromContext();
		String authenticatedUserId = authUser.getCodePA();
		log.info("1 => Load  Authenticated user {}", authenticatedUserId);

		// authenticate the Partner by CODEPARTNER_LABEL , "codeSIRET"
		List<GroupLDAP> groupPartnerLDAPs = Collections.emptyList();
		try {
			groupPartnerLDAPs = this.ldapResourceClient
					.getGroups(Map.of(CODEPARTNER_LABEL, codePartner/* , "codeSIREN", codeSIREN */));
			log.info("2 => Identify a partner with codePartner  {} (no identification with SIRET code)",
					codePartner/* , codeSIREN */);
		} catch (HappyBusinessException errorCallApi) {
			if (errorCallApi.getCode().endsWith("404")) {
				log.error("2 => No partner found with codePartner  {} ", codePartner, /* codeSIREN, */
						errorCallApi);
				this.applicationEventPublisher.publishEvent(new TraceErrorEvent(this, "TR-007", authenticatedUserId,
						Map.of(CODEPARTNER_LABEL, codePartner)));
			} else {
				log.error("An error has occurred ", errorCallApi);
				throw errorCallApi;
			}
		}

		// check no group has been created before => no init B2B relationship has been
		// done before
		List<GroupLDAP> habilitationGestionnaireGroupLDAPs = new ArrayList<>();
		try {
			habilitationGestionnaireGroupLDAPs = this.ldapResourceClient.getGroups(
					Map.of(CODEPARTNER_LABEL, codePartner, "habilitation", "Gestionnaire", GROUP_TYPE, "profilGroup"));
		} catch (HappyBusinessException errorCallApi) {
			if (!errorCallApi.getCode().endsWith("404")) {
				log.error("An error has occurred ", errorCallApi);
				throw errorCallApi;
			} else {
				log.info("3 => verify that no init B2B relationship has been found for the partner {}", codePartner);
			}

		}
		if (habilitationGestionnaireGroupLDAPs != null && !habilitationGestionnaireGroupLDAPs.isEmpty()) {
			log.error("The B2B relationship has been already initialized for this partner {}",
					habilitationGestionnaireGroupLDAPs.get(0).getCodePartner());
			PartnerDTO partnerDTO = this.groupMapper.toPartnerDTO(groupPartnerLDAPs.get(0));
			this.applicationEventPublisher.publishEvent(new TraceErrorEvent(this, "TR-044", authenticatedUserId,
					Map.of("partnerDTO", this.utilsMapper.serializeDTOAsString(partnerDTO))));
		}

		PartnerDTO partnerDTO = this.groupMapper.toPartnerDTO(groupPartnerLDAPs.get(0));
		partnerDTO.setInitB2B(false);
		return partnerDTO;
	}

	public GroupLDAP findPartnerByCodePartner(String codePartner) {

		if (codePartner.length() != 11) {
			throw new HappyClientException(Status.BAD_REQUEST, BAD_ID_PATERN, BAD_CODEPATERN_PATERN_MSG);
		}
		return this.ldapResourceClient.getGroups(Map.of(CODEPARTNER_LABEL, codePartner)).get(0);
	}

	UserDTO checkAuthUser() {
		// session's user
		UserDTO authUser = this.securityServiceUtils.loadAuthenticatedUserFromContext();
		String authenticatedUserId = authUser.getCodePA();
		log.info(LOAD_USER_MSG, authenticatedUserId);

		return authUser;
	}

	private void checkEmailExistence(UserDTO userDTO) {
		// check email's existence
		try {
			log.info(CHECK_EMAIL_EXISTENCE, userDTO.getEmail());
			List<UserLDAP> users = this.ldapResourceClient
					.getUsers(Map.ofEntries(entry(EMAIL_LABEL, userDTO.getEmail())));
			log.error(EMAIL_ALREADY_ASSIGNED, users.stream().map(UserLDAP::getCodePA).collect(Collectors.joining(",")));
			throw new HappyClientException(Status.BAD_REQUEST, EMAIL_ALREADY_EXIST_CODE, EMAIL_ALREADY_EXIST_SHORTLIB);
		} catch (HappyBusinessException errorCallApi) {
			if (!errorCallApi.getCode().endsWith("404")) {
				log.error(ERROR_OCCURED, errorCallApi);
				throw errorCallApi;
			}
		}
	}

	public UserDTO createVendorUser(UserDTO userDTO) {

		UserDTO authUser = checkAuthUser();

		checkEmailExistence(userDTO);

		// create user
		UserLDAP userLDAP = UserLDAP.newInstanceOfUser(userDTO);
		userLDAP.setCodePartner(userDTO.getCodePartner());
		GroupLDAP partnerGroupLDAP = this.findPartnerByCodePartner(userDTO.getCodePartner());
		userLDAP.setCodePartnerParent(partnerGroupLDAP.getCodePartnerParent());
		//// add partner authentication type
		userLDAP.setAuthType(partnerGroupLDAP.getAuthType());
		userLDAP.formatInput();
		userLDAP = this.ldapResourceClient.createUser(userLDAP);
		UserDTO createdUserDTO = this.userMapper.toDTO(userLDAP, false, false);

		String codePA = userLDAP.getCodePA();
		// Event TR010: Création d'un utilisateur validée
		Event eventTR010 = this.eventService.generateEvent("TR-010", authUser, Map.ofEntries());
		eventTR010.setUserTarget(userLDAP.getCodePA());

		// add event params
		eventTR010.setParams(Map.of(USER_DTO, this.utilsMapper.serializeDTOAsString(createdUserDTO)));

		this.applicationEventPublisher.publishEvent(eventTR010);
		log.info("create user account {}", codePA);

		// add user to Partner Group
		this.ldapResourceClient.addMember(partnerGroupLDAP.getName(), codePA);
		log.info("add the created user to the partner's group {} <- {}", partnerGroupLDAP.getName(),
				userLDAP.getCodePA());

		// params of the user notification
		Map<String, String> paramsUser = new HashMap<>();
		paramsUser.put(PERSONALTITLE_LABEL, userLDAP.getPersonalTitle());
		paramsUser.put("nom", userLDAP.getNom() + " " + userLDAP.getPrenom());
		paramsUser.put(CODEPA_LABEL, userLDAP.getCodePA());

		// STRONG AUTH
		// Check if partner is on strong authentication	
		if (groupUtils.isStrongAuth(partnerGroupLDAP)) {
			// generate unique URL
			UniqueURL enrollmentUrl = UniqueURL.builder().context("parcours-enrolement").token(UUID.randomUUID().toString())
					.valid(true).build();
			log.info("generate an unique url for user enrollment operation {}", userLDAP.getCodePA());
		
			generateAndPublishEventTR079(enrollmentUrl, userLDAP, authUser);
			
		} else {
			UniqueURL uniqueURL = UniqueURL.builder().context("initPassword").token(UUID.randomUUID().toString())
					.valid(true).build();
			log.info("generate an unique url for the password's init operation {}", uniqueURL.getId());
			
			// SIMPLE AUTH - generate unique URL
			paramsUser.put("urlInitPswd", generateUniqueURL(uniqueURL));
			paramsUser.put("loginCode", MOT_DE_PASSE);
			Entry<String, Map<String, String>> userNotifParams = entry("user", paramsUser);
			
		// Event : password init
		// link // NOT-001
		Event eventTR049 = this.eventService.generateEvent("TR-049", this.userMapper.toDTO(userLDAP, false, false),
				Map.ofEntries(userNotifParams));
		
			Request request = eventTR049.getRequest();
			request.setUniqueURL(uniqueURL);
			uniqueURL.setRequest(request);
			request.setRecipient(userLDAP.getCodePA());
			request.setParams(Map.ofEntries(entry("gestionnaireName",
			authUser.getCodePA() + " " + authUser.getPrenom() + " " + authUser.getNom())));


			// add event params
			Entry<String, String> authUserDTOentry = entry(AUTH_USER_DTO, this.utilsMapper.serializeDTOAsString(authUser));
			Entry<String, String> userDTOentry = entry(USER_DTO, this.utilsMapper.serializeDTOAsString(createdUserDTO));
			eventTR049.setParams(Map.ofEntries(authUserDTOentry, userDTOentry));

		this.applicationEventPublisher.publishEvent(eventTR049);
		log.info("generate the event [TR005] without support notif {}", eventTR049.getId());
		}

		// add the smartconnect habilitation to the user
		userDTO.getSmartConnectHabilitationDTOs().stream()
				.filter(sh -> "GESTIONNAIRE".equals(sh.getHabilitation().toString())).forEach(sh -> {
					String groupName = "SG_SMARTCONNECT_Gestionnaires_" + sh.getCodePartner();
					this.ldapResourceClient.addMember(groupName, codePA);
					// Event TR014: Affectation de droit à une application
					Event eventTR008 = this.eventService.generateEvent(TR008, authUser, Map.ofEntries());
					eventTR008.setUserTarget(codePA);
					Entry<String, String> reqEventTR008POS = entry(POINTOFSALE_LABEL,
							partnerGroupLDAP.getPointOfSales().equals(partnerGroupLDAP.getCompany()) ? partnerGroupLDAP.getPointOfSales()
									: partnerGroupLDAP.getPointOfSales() + " - " + partnerGroupLDAP.getCompany());
					eventTR008.getRequest().setParams(Map.ofEntries(reqEventTR008POS));
					eventTR008.setParams(Map.ofEntries(
							entry(SMARTCONNECT_HABILITATION_DTO, this.utilsMapper.serializeDTOAsString(sh)),
							entry(USER_DTO, this.utilsMapper.serializeDTOAsString(userDTO))));
					this.applicationEventPublisher.publishEvent(eventTR008);
					log.info("add user to the gestionnaire's group {} <- {}", groupName, codePA);
				});

		// add the frontal habilitation to the user
		userDTO.getFrontalHabilitationDTOs().stream().forEach(fh -> {
			String groupName = "SG_" + fh.getFrontal() + "_" + fh.getHabilitation()
					+ groupUtils.returnSuffix(fh.getFrontal(), fh.getHabilitation());
			this.ldapResourceClient.addMember(groupName, codePA);
			// Event TR014: Affectation de droit à une application
			// pas d'event d'affectation de profil pour une création
			Event eventTR014 = this.eventService.generateEvent("TR-014", authUser, Map.ofEntries());
			eventTR014.setUserTarget(codePA);
			// Ajout d'une request pour l'event TR014 afin de tracer les frontaux habilités
			Request requestFrontalHabilitation = eventTR014.getRequest();
			Map<String, String> params = new HashMap<>();
			params.put("addedProfil", fh.getHabilitation());
			params.put(FRONTAL_LABEL, fh.getFrontal());
			requestFrontalHabilitation.setParams(params);

			// add event params
			eventTR014.setParams(Map.ofEntries(entry(USER_DTO, this.utilsMapper.serializeDTOAsString(userDTO)),
					entry(FRONTAL_HABILITATION_DTO, this.utilsMapper.serializeDTOAsString(fh))));

			this.applicationEventPublisher.publishEvent(eventTR014);
			log.info("add user to the frontal group {} <- {}", groupName, codePA);
		});

		return createdUserDTO;
	}

	public UserDTO createFirstGestionnaireUser(UserDTO userDTO) {

		// session's user
		UserDTO authUser = this.securityServiceUtils.loadAuthenticatedUserFromContext();
		String authenticatedUserId = authUser.getCodePA();
		log.info("1 => Load  Authenticated user {}", authenticatedUserId);

		// authenticate and get the Partner again
		PartnerDTO partnerDTO = this.preparePartnerForInitialization(
				userDTO.getPartnerDTO().getCodePartner()/* , userDTO.getPartnerDTO().getCodeSIREN() */);
		log.info("2 => preparePartnerForInitialization {}", partnerDTO.getCodePartner());

		// check email's existence
		try {
			log.info("3 => check email's existence {}", userDTO.getEmail());
			List<UserLDAP> users = this.ldapResourceClient
					.getUsers(Map.ofEntries(entry(EMAIL_LABEL, userDTO.getEmail())));
			log.error("3 => mail's address already assigned to an existing user(s) {}",
					users.stream().map(UserLDAP::getCodePA).collect(Collectors.joining(",")));
			throw new HappyClientException(Status.BAD_REQUEST, EMAIL_ALREADY_EXIST_CODE, EMAIL_ALREADY_EXIST_SHORTLIB);
		} catch (HappyBusinessException errorCallApi) {
			if (!errorCallApi.getCode().endsWith("404")) {
				log.error("3 => an error is occured during the verification ", errorCallApi);
				throw errorCallApi;
			}
		}

		LocalDateTime now = LocalDateTime.now();

		// create the first Gestionnaire Member
		UserLDAP userLDAP = UserLDAP.newInstanceOfUser(userDTO);
		userLDAP.setCodePartner(partnerDTO.getCodePartner());
		userLDAP.setCodePartnerParent(partnerDTO.getCodePartnerParent());
		userLDAP.setLastReviewDate(now.format(reviewDtf));
		userLDAP.formatInput();
		userLDAP = this.ldapResourceClient.createUser(userLDAP);
		log.info("4 => create user account {}", userLDAP.getCodePA());

		// create the first group of Gestionnaires/SMARTCONNECT/Partner
		GroupLDAP gestionnaireGroupLDAP = GroupLDAP.newInstanceOfGroup(partnerDTO.getCodePartner(), "Gestionnaire",
				"profilGroup");
		gestionnaireGroupLDAP.generateGroupName(SMARTCONNECT_LABEL, "s");
		gestionnaireGroupLDAP = this.ldapResourceClient.create(gestionnaireGroupLDAP);
		log.info("4 => create gestionnaire's group {}", gestionnaireGroupLDAP.getName());

		// add user to Partner Group
		GroupLDAP partnerGroupLDAP = this.ldapResourceClient
				.getGroups(
						Map.of(CODEPARTNER_LABEL, partnerDTO.getCodePartner(), "codeSIREN", partnerDTO.getCodeSIREN()))
				.get(0);
		this.ldapResourceClient.addMember(partnerGroupLDAP.getName(), userLDAP.getCodePA());
		log.info("5 => add the created user to the partner's group {} <- {}", partnerGroupLDAP.getName(),
				userLDAP.getCodePA());

		// params of the user notification
		Map<String, String> paramsUser = new HashMap<>();
		paramsUser.put(PERSONALTITLE_LABEL, userLDAP.getPersonalTitle());
		paramsUser.put("nom", userLDAP.getNom() + " " + userLDAP.getPrenom());
		paramsUser.put(CODEPA_LABEL, userLDAP.getCodePA());

		UniqueURL uniqueURL =  null;

		log.info("****** DETERMINE AUTH : {}", userDTO.getAuthType());

		// STRONG AUTH
		// Check if user user the strong authentication
		String enrollmentUrl = "";
		if (userUtils.isStrongAuth(userLDAP)) {
			uniqueURL = UniqueURL.builder().context("parcours-enrolement").token(UUID.randomUUID().toString())
					.valid(true).build();
			log.info("generate an unique url for the password's init operation {}", uniqueURL.getId());
			enrollmentUrl = this.ldapResourceClient.generateEnrollmentUrl(userLDAP.getCodePA());
			paramsUser.put("urlInitPswd", enrollmentUrl);
			paramsUser.put("loginCode", CODE_PIN);
		} else {
			uniqueURL = UniqueURL.builder().context("initPassword").token(UUID.randomUUID().toString())
					.valid(true).build();
			log.info("generate an unique url for the password's init operation {}", uniqueURL.getId());
			// SIMPLE AUTH - generate unique URL
			paramsUser.put("urlInitPswd", generateUniqueURL(uniqueURL));
			paramsUser.put("loginCode", MOT_DE_PASSE);
		}
		Entry<String, Map<String, String>> userNotifParams = entry("user", paramsUser);

		StringBuilder posBld = new StringBuilder();
		if (!partnerGroupLDAP.getPointOfSales().equals(partnerGroupLDAP.getCompany())) {
			posBld.append(partnerGroupLDAP.getPointOfSales());
			posBld.append(" - ");
			posBld.append(partnerGroupLDAP.getCompany());
		} else {
			posBld.append(partnerGroupLDAP.getPointOfSales());
		}
		var groupLDAPSectionCode = partnerGroupLDAP.getSectionCode();

		// add user to group of Gestionnaires/SMARTCONNECT/Partner
		this.ldapResourceClient.addMember(gestionnaireGroupLDAP.getName(), userLDAP.getCodePA());
		log.info("8 => add user to the gestionnaire's group {} <- {}", gestionnaireGroupLDAP.getName(),
				userLDAP.getCodePA());

		// Attribution des droits gestionnaire
		// Event : Attribution des droits gestionnaire
		Event eventTR008 = this.eventService.generateEvent(TR008, authUser, Map.of());

		// add params event
		SmartConnectHabilitationDTO sch = SmartConnectHabilitationDTO.builder()
				.codePartner(userDTO.getPartnerDTO().getCodePartner()).company(userDTO.getPartnerDTO().getCompany())
				.habilitation(Role.GESTIONNAIRE).pointOfSales(userDTO.getPartnerDTO().getPointOfSales()).build();
		eventTR008.setParams(
				Map.ofEntries(entry(SMARTCONNECT_HABILITATION_DTO, this.utilsMapper.serializeDTOAsString(sch)),
						entry(USER_DTO, this.utilsMapper.serializeDTOAsString(userDTO))));

		this.applicationEventPublisher.publishEvent(eventTR008);
		log.info("9 => generate the event [TR008] {}", eventTR008.getId());

		// add group of Gestionnaires/SMARTCONNECT/Partner to SmartConnect Group
		GroupLDAP smartConnectGroupLDAP = this.ldapResourceClient.getGroupByName("SG_SMARTCONNECT");
		this.ldapResourceClient.addMember(smartConnectGroupLDAP.getName(), gestionnaireGroupLDAP.getName());
		log.info("10 => add gestionnaire's group to SmartConnect's group {} <- {}", smartConnectGroupLDAP.getName(),
				gestionnaireGroupLDAP.getName());

		// add the default frontal's habilitation which the partner has to the user
		for (String dn : partnerGroupLDAP.getMemberOf()) {

			// get only frontal group
			if (!dn.toUpperCase().startsWith("CN=SG_SMARTCONNECT")) {

				GroupLDAP frontalGroupLDAP = this.ldapResourceClient
						.getGroupByName(this.configService.extractCnFromDN(dn));

				String defaultProfil = frontalGroupLDAP.getDefaultProfil();

				// get the group with the default profil habilitation : SG_CEASY_Vendeurs if the
				// default profil was VENDEUR
				String defaultProfilGroupName = frontalGroupLDAP.getMembers().stream().filter(dnHabilitation -> {
					String name = this.configService.extractCnFromDN(dnHabilitation);
					return name.toUpperCase().contains(defaultProfil);
				}).map(dnHabilitation -> this.configService.extractCnFromDN(dnHabilitation)) // extract the name from
						// the dn
						.findAny().orElseThrow(
								() -> new HappyBusinessException("CREATE_FIRST_MANAGER", "The default group profil ["
										+ defaultProfil + "] of " + frontalGroupLDAP.getDn() + " not found"));

				this.ldapResourceClient.addMember(defaultProfilGroupName, userLDAP.getCodePA());
				log.info("11 => add user to the frontal's group {} <- {}", defaultProfilGroupName,
						userLDAP.getCodePA());
			}

		}

		// set the last review date parameter as the initilisation date
		GroupLDAP updatedPartner = GroupLDAP.builder().name(partnerGroupLDAP.getName())
				.lastReviewDate(now.format(reviewDtf)).build();
		this.ldapResourceClient.updateGroup(updatedPartner);
		log.info("12 => Last review date parameter setted as {} ", now.format(reviewDtf));

		// add event params
		userDTO = this.userMapper.toDTO(userLDAP, true, false);
		if (null != groupLDAPSectionCode) {
			Entry<String, Map<String, String>> cacfNotifParams = entry("formateur",
					Map.ofEntries(entry("sectionCode", groupLDAPSectionCode),
							entry("numApporteur", userLDAP.getCodePartner()), entry(POINTOFSALE_LABEL, posBld.toString()),
							entry("date", now.format(dtf)), entry("userAuth", authUser.getPrenom() + " " + authUser
									.getNom()), /*
							 * Utilisation du nom-prénom pour les users s'authentifiant avec login CACF
							 */
							entry("nameFirstGestionnaire",
									userLDAP.getPersonalTitle() + " " + userLDAP.getPrenom() + " " + userLDAP.getNom()),
							entry("codePAFirstGestionnaire", userLDAP.getCodePA()),
							entry("emailFirstGestionnaire", userLDAP.getEmail())));

			// Event : Initialisation de la relation commerciale digitale + password init
			// link
			
			if (userUtils.isStrongAuth(userLDAP)) {
				UniqueURL uniqueUrl = UniqueURL.builder().context("parcours-enrolement").token(UUID.randomUUID().toString())
						.valid(true).build();
				log.info("generate an unique url for user enrollment operation {}", userLDAP.getCodePA());
				generateAndPublishEventTR079(uniqueURL, userLDAP, authUser);
				
			} else {
				
			Event eventTR005 = this.eventService.generateEvent("TR-005", this.userMapper.toDTO(userLDAP, false, false),
					Map.ofEntries(userNotifParams, cacfNotifParams));
			Request request = eventTR005.getRequest();
			request.setUniqueURL(uniqueURL);
			uniqueURL.setRequest(request);
			request.setRecipient(userLDAP.getCodePA());

			eventTR005.setParams(Map.of(USER_DTO, this.utilsMapper.serializeDTOAsString(userDTO)));
			this.applicationEventPublisher.publishEvent(eventTR005);
			log.info("7 => generate the event [TR005] {}", eventTR005.getId());
			}
		} else {
			log.warn("prevent sending event to no animators on {}", userLDAP.getCodePartner());
		}

		return userDTO;

	}
	
	/**
	 * Generate and publish TR-079 event: the user is created with strong authentication
	 * and received the NOT-070 for account initialization
	 * 
	 * @param enrollmentUrl
	 * @param userLDAP
	 * @param authUser
	 */
	private void generateAndPublishEventTR079 (UniqueURL uniqueURL, UserLDAP userLDAP, UserDTO authUser) {
		
		Entry<String, Map<String, String>> userNotifParams = entry("user", Map.ofEntries(entry(CODEPA_LABEL, userLDAP.getCodePA()),
				entry(PERSONALTITLE_LABEL, userLDAP.getPersonalTitle()), entry("nom", userLDAP.getNom() + " " + userLDAP.getPrenom()),
				entry("uniqueURL", generateUniqueURL(uniqueURL)), entry(CODEPARTNER_LABEL, userLDAP.getCodePartner())));
				
		Event eventTR079 = this.eventService.generateEvent("TR-079", this.userMapper.toDTO(userLDAP, false, false),
						Map.ofEntries(userNotifParams));
		
		UserDTO createdUserDTO = this.userMapper.toDTO(userLDAP, false, false);

		eventTR079.getNotifications();
		log.info("Generate event TR-079 {}", eventTR079.getId());
		
		Request request = eventTR079.getRequest();
		request.setUniqueURL(uniqueURL);
		uniqueURL.setRequest(request);
		request.setRecipient(userLDAP.getCodePA());
		
		// add event params
		Entry<String, String> authUserDTOentry = entry(AUTH_USER_DTO, this.utilsMapper.serializeDTOAsString(authUser));
		Entry<String, String> userDTOentry = entry(USER_DTO, this.utilsMapper.serializeDTOAsString(createdUserDTO));
		eventTR079.setParams(Map.ofEntries(authUserDTOentry, userDTOentry));
		this.applicationEventPublisher.publishEvent(eventTR079);
		log.info("Publish event {}", eventTR079.getId());

		
	}

	public List<UserDTO> findManagersOfPartner(MultivaluedMap<String, String> queryParameters) {
		if (queryParameters.isEmpty()) {
			throw new HappyValidationException("NO_PARAM",
					"No parameters specified. At least one parameter is required");
		}
		if (!queryParameters.containsKey(CODEPARTNER_LABEL)) {
			log.error("Must have codePartner param");
			throw new HappyValidationException("PARAM_NOT_SUPPORTED", "Must have codePartner param");
		}

		String codePartner = queryParameters.get(CODEPARTNER_LABEL).get(0);

		return this.ldapResourceClient.getManagersOfPartner(codePartner).stream()
				.map(userLDAP -> this.userMapper.toDTO(userLDAP, false, false)).collect(Collectors.toList());
	}

	public List<UserDTO> findByFilter(MultivaluedMap<String, String> queryParameters) {

		// session's user
		UserDTO authUser = this.securityServiceUtils.loadAuthenticatedUserFromContext();
		String authenticatedUserId = authUser.getCodePA();
		// others profiles [ Formateur, ADMIN] didn't need to get their partner group

		log.info("findByFilter - user authorizations roles : {} ", authUser.getSmartConnectHabilitationDTOs());

		// recuperation du codePArtner parent depuis le partner et non le user
		log.info(LOAD_USER_MSG, authenticatedUserId);

		if (queryParameters.isEmpty()) {
			throw new HappyValidationException("NO_PARAM",
					"No parameters specified. At least one parameter is required");
		}

		log.info("Initial query params {} ", queryParameters);
		surchargeParamsWithPartnerCode(authUser, queryParameters);
		// // recherche d'un user avec le pos et la company d'un apporteur

		if (!this.validateUserFilters(queryParameters)) {
			throw new HappyValidationException("PARAM_NOT_SUPPORTED",
					"One or more parameters request not supported" + Collections.singletonList(queryParameters));
		}
		log.info("Final query params {}", queryParameters);
		Map<String, String> filters = new HashMap<>();

		queryParameters.forEach((k, v) -> filters.put(k, v.get(0)));
		log.info("filters {}", filters);
		List<UserDTO> userLDAPs = new ArrayList<>();

		// we try to call the api, in case it fail we damage control to avoid failing review
		if (!filters.isEmpty()) {
			try {
				userLDAPs = this.ldapResourceClient.getUsers(filters).stream()
						// Only return the users with a compliant codePA
						.filter(userLDAP -> isUserCode(userLDAP.getCodePA())).map(userLDAP -> {
							return this.userMapper.toSmallDTO(userLDAP);
						}).collect(Collectors.toList());
			} catch (HappyBusinessException e) {
				if (e.getCode().endsWith("404")) {
					log.error("No user has been found with the params ", e);
				} else {
					log.error("an error is occurred ", e);
					throw e;
				}
			}
		}
		
		return userLDAPs;
	}

	private String surchargeForAdminFormateur(Map<String, String> partnerQueryParam) {
		String groups = "";
		try {
			groups = this.ldapResourceClient.getGroups(partnerQueryParam).stream().map(GroupLDAP::getCodePartner)
					.collect(Collectors.joining(";"));
		} catch (HappyBusinessException errorCallApi) {
			if (errorCallApi.getCode().endsWith("404")) {
				log.error("2 => No partner found with codePartner  {} ", partnerQueryParam, errorCallApi);
			} else {
				log.error("An error has occurred ", errorCallApi);
				throw errorCallApi;
			}
		}
		return groups;
	}

	private String surchargeForGestionnaire(UserDTO authUser, String pos, String company) {
		List<GroupLDAP> authUserMAnagedPartners = this.securityServiceUtils.getAuthUserManagedPartners();
		log.info("Found {} partners managed by user {}", authUserMAnagedPartners.size(), authUser.getCodePA());
		StringBuilder bld = new StringBuilder();
		for (GroupLDAP authUserManagedPartner : authUserMAnagedPartners) {
			log.info("Check if company = {} and/or pos = {} for partner {}", company, pos,
					authUserManagedPartner.getCodePartner());
			generatePartnerCodeList(bld, company, pos, authUserManagedPartner);
		}

		return bld.toString();
	}

	private String surchargeParams(UserDTO authUser, Map<String, String> partnerQueryParam) {
		String codePartnerFilter = "";

		// ADMIN & FORMATEUR
		if (Role.ADMIN == authUser.getRole() || Role.FORMATEUR == authUser.getRole()) {
			codePartnerFilter = this.surchargeForAdminFormateur(partnerQueryParam);
		}
		// GESTIONNAIRE
		else if (Role.GESTIONNAIRE == authUser.getRole()) {
			codePartnerFilter = this.surchargeForGestionnaire(authUser, partnerQueryParam.get("pointOfSales"),
					partnerQueryParam.get(COMPANY_LABEL));
		}

		return codePartnerFilter;
	}

	/**
	 * Transform the pos and/or company params to a code partner list, and remove
	 * those params from the user params for gestionnaire user, serach only in the
	 * manager groups
	 *
	 * @param authUser
	 * @param queryParameters
	 */
	private MultivaluedMap<String, String> surchargeParamsWithPartnerCode(UserDTO authUser,
			MultivaluedMap<String, String> queryParameters) {
		// IF COMPANY OR POINT OF SALES PARAMS PRESENT
		if (queryParameters.containsKey(POINTOFSALE_LABEL) || queryParameters.containsKey(COMPANY_LABEL)) {
			Map<String, String> partnerQueryParam = new HashMap<>();
			String codePartnerFilter = "";
			String pos = "";
			String company = "";
			if (queryParameters.containsKey(POINTOFSALE_LABEL)) {
				pos = queryParameters.get(POINTOFSALE_LABEL).get(0);
				partnerQueryParam.put("pointOfSales", pos);
				queryParameters.remove(POINTOFSALE_LABEL);
				this.securityServiceUtils.cleanSearchParam(pos);
				codePartnerFilter = surchargeParams(authUser, partnerQueryParam);
			}
			partnerQueryParam = new HashMap<>();
			if (queryParameters.containsKey(COMPANY_LABEL)) {
				company = queryParameters.get(COMPANY_LABEL).get(0);
				partnerQueryParam.put(COMPANY_LABEL, company);
				queryParameters.remove(COMPANY_LABEL);
				this.securityServiceUtils.cleanSearchParam(company);
				if (!"".contentEquals(codePartnerFilter)) {
					codePartnerFilter = codePartnerFilter + ";" + surchargeParams(authUser, partnerQueryParam);
				} else {
					codePartnerFilter = surchargeParams(authUser, partnerQueryParam);
				}
			}

			if (!"".contentEquals(codePartnerFilter)) {
				queryParameters.add(CODEPARTNER_LABEL, codePartnerFilter);
			}

		}
		// SEARCH with only userLDAP properties param
		else if (!queryParameters.containsKey(CODEPARTNER_LABEL) && Role.GESTIONNAIRE == authUser.getRole()) {
			String codePartnerFilter = authUser.getSmartConnectHabilitationDTOs().stream()
					.map(SmartConnectHabilitationDTO::getCodePartner).collect(Collectors.joining(";"));
			queryParameters.add(CODEPARTNER_LABEL, codePartnerFilter);
		}

		return queryParameters;

	}

	private StringBuilder generatePartnerCodeList(StringBuilder bld, String company, String pos,
			GroupLDAP authUserManagedPartner) {

		boolean searchByCompany = "".equals(pos) && !"".equals(company);
		boolean searchByPOS = !"".equals(pos) && "".equals(company);
		boolean searchByPOSandCompany = !"".equals(pos) && !"".equals(company);

		if (searchByCompany && authUserManagedPartner.getCompany().toUpperCase()
				.contains(this.securityServiceUtils.cleanSearchParam(company).toUpperCase())) {
			log.info("searchByCompany {}", this.securityServiceUtils.cleanSearchParam(company));
			bld.append(authUserManagedPartner.getCodePartner());
			bld.append(';');
		} else if (searchByPOS && authUserManagedPartner.getPointOfSales().toUpperCase()
				.contains(this.securityServiceUtils.cleanSearchParam(pos).toUpperCase())) {
			log.info("searchByPOS");
			bld.append(authUserManagedPartner.getCodePartner());
			bld.append(';');
		} else if (searchByPOSandCompany
				&& authUserManagedPartner.getCompany().toUpperCase()
						.contains(this.securityServiceUtils.cleanSearchParam(company).toUpperCase())
				&& authUserManagedPartner.getPointOfSales().toUpperCase()
						.contains(this.securityServiceUtils.cleanSearchParam(pos).toUpperCase())) {
			log.info("searchByPOSandCompany");
			bld.append(authUserManagedPartner.getCodePartner());
			bld.append(';');
		} else {
			log.warn("No result with this parameters : role = GESTIONNAIRE, company = {}, pos={}", company, pos);
		}

		return bld;
	}

	public Optional<UserDTO> getUserByCodePAWithRoles(String codePA) {

		UserLDAP userLDAP = this.ldapResourceClient.getUserByMatricule(codePA);

		return Optional.of(this.userMapper.toDTO(userLDAP, true, false));

	}

	public boolean validateUserFilters(MultivaluedMap<String, String> filters) {
		Set<String> fields = Arrays.stream(UserDTO.class.getDeclaredFields())
				.map(field -> field.getName().toLowerCase()).collect(Collectors.toSet());
		Set<String> filterKeys = filters.keySet().stream().map(String::toLowerCase).collect(Collectors.toSet());
		fields.add(LIMIT_LABEL);
		return fields.containsAll(filterKeys);

	}

	public UserDTO submitUserCreation(UserDTO userDTO) {

		// session's user
		UserDTO authUser = this.securityServiceUtils.loadAuthenticatedUserFromContext();
		String authenticatedUserId = authUser.getCodePA();
		log.info(LOAD_USER_MSG, authenticatedUserId);

		// find partner
		PartnerDTO partnerDTO = this.groupMapper.toPartnerDTO(this.findPartnerByCodePartner(userDTO.getCodePartner()));
		// add partner authentication type
		userDTO.setAuthType(partnerDTO.getAuthType());
		userDTO.setCodePartnerParent(userDTO.getPartnerDTO().getCodePartnerParent());
		userDTO.setSmartConnectHabilitationDTOs(userDTO.getSmartConnectHabilitationDTOs().stream().map(sh -> {
			PartnerDTO partnerDTO1 = this.groupMapper.toPartnerDTO(this.findPartnerByCodePartner(sh.getCodePartner()));
			sh.setPointOfSales(partnerDTO1.getPointOfSales());
			sh.setCompany(partnerDTO1.getCompany());
			return sh;
		}).collect(Collectors.toList()));

		if (!userDTO.isCommis()) {

			// generate unique URL
			UniqueURL uniqueURL = UniqueURL.builder().context("users/confirm/userCreation")
					.token(UUID.randomUUID().toString()).valid(true).build();
			// params of the user notification
			Entry<String, Map<String, String>> userNotifParams = entry("user",
					Map.ofEntries(entry("urlConfirmNewuser", generateUniqueURL(uniqueURL)),
							entry(CODEPARTNER_LABEL, userDTO.getCodePartner())));
			log.info("generate an unique url for the user's creation request {}", uniqueURL.getToken());
			// TR009
			Event eventTR009 = this.eventService.generateEvent("TR-009", authUser, Map.ofEntries(userNotifParams));

			Request request = eventTR009.getRequest();
			request.setUniqueURL(uniqueURL);
			uniqueURL.setRequest(request);
			request.setRecipient(authUser.getCodePA());

			userDTO.setPartnerDTO(partnerDTO);

			try {
				Entry<String, String> userParamEntry = entry(USER_DTO, this.mapper.writeValueAsString(userDTO));
				request.setParams(Map.ofEntries(userParamEntry));
			} catch (JsonProcessingException e) {
				throw new HappyBusinessException(USER_JSON_ERROR_CODE, USER_JSON_ERROR_SHORTLIB, e);
			}

			// add event params
			eventTR009.setParams(Map.of(USER_DTO, this.utilsMapper.serializeDTOAsString(userDTO)));

			this.applicationEventPublisher.publishEvent(eventTR009);

			log.info("generate the event [TR009] {}", eventTR009.getId());
		}
		return userDTO;
	}

	public UserDTO submitCommisCreation(UserDTO userDTO) {
		// session's user
		UserDTO authUser = this.securityServiceUtils.loadAuthenticatedUserFromContext();
		String authenticatedUserId = authUser.getCodePA();
		log.info(LOAD_USER_MSG, authenticatedUserId);
		String partnerGestionnaire = (authUser.getPartnerDTO().getPointOfSales()
				.equals(authUser.getPartnerDTO().getCompany()) ? authUser.getPartnerDTO().getPointOfSales()
						: authUser.getPartnerDTO().getPointOfSales() + "-" + authUser.getPartnerDTO().getCompany());
		if (Role.ADMIN == authUser.getRole() || Role.GESTIONNAIRE == authUser.getRole()) {
			DateTimeFormatter dateTimeFormat = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss");
			String now = dateTimeFormat.format(LocalDateTime.now());
			// NOT023 to Managers:
			Entry<String, Map<String, String>> cacfNotifParams = entry("gestionVendeur",
					Map.ofEntries(entry("titleNewCommis", userDTO.getPersonalTitle()),
							entry("nameNewCommis", userDTO.getNom()), entry("firstnameNewCommis", userDTO.getPrenom()),
							entry("levelNewCommis", userDTO.getLevel()), entry("partnerCode", userDTO.getCodePartner()),
							entry("date", now), entry("nameGestionnaire", authUser.getNom()),
							entry("firstnameGestionnaire", authUser.getPrenom()),
							entry("codePAGestionnaire", authUser.getCodePA()),
							entry("partnerCodeGestionnaire", authUser.getPartnerDTO().getCodePartner()),
							entry("partnerSectionGestionnaire", authUser.getPartnerDTO().getSectionCode()),
							entry("partnerGestionnaire", partnerGestionnaire)));
			Entry<String, Map<String, String>> userNotifParams = entry("user",
					Map.ofEntries(entry("levelNewCommis", userDTO.getLevel()),
							entry("nameNewCommis", userDTO.getPrenom() + " " + userDTO.getNom().toUpperCase())));
			Event eventTR066 = this.eventService.generateEvent("TR-066", authUser,
					Map.ofEntries(userNotifParams, cacfNotifParams));
			this.applicationEventPublisher.publishEvent(eventTR066);
			log.info("generate the event [TR066] {}", eventTR066.getId());
		} else {
			throw new HappyForbiddenException(FORBIDDEN_CODE,
					THE_USER + authenticatedUserId + " does not have the autority to perform this action");
		}

		return userDTO;
	}

	@Autowired
	private ObjectMapper mapper;

	public UserDTO addEmail(UserDTO userDTO) {
		UserDTO authUser = checkAuthUser();

		checkEmailExistence(userDTO);

		UserDTO userUpdatedEmail = this.updateUser(userDTO);

		// add notif to user added Email
		// NOT054 to concerned user:
		Entry<String, Map<String, String>> concernedNotificationParams = entry(CONCERNED,
				Map.of(CODEPA_LABEL, userDTO.getCodePA(), EMAIL_LABEL, userDTO.getEmail(), "nomManager",
						authUser.getNom(), "prenomManager", authUser.getPrenom()));
		Event event067 = this.eventService.generateEvent("TR-067", authUser,
				Map.ofEntries(concernedNotificationParams));
		this.applicationEventPublisher.publishEvent(event067);

		return userUpdatedEmail;

	}

	public UserDTO updateUser(UserDTO userDTO) {
		// find partner
		PartnerDTO partnerDTO = this.groupMapper.toPartnerDTO(this.findPartnerByCodePartner(userDTO.getCodePartner()));
		// add partner authentication type
		userDTO.setAuthType(partnerDTO.getAuthType());

		this.ldapResourceClient.updateUser(UserLDAP.toLDAP(userDTO));
		return userDTO;
	}

	public void suspendUsers(List<UserDTO> usersToSuspend) {

		UserDTO authUser = this.securityServiceUtils.loadAuthenticatedUserFromContext();
		String authenticatedUserId = authUser.getCodePA();
		log.info(LOAD_USER_MSG, authenticatedUserId);

		// suspend Users
		usersToSuspend.forEach(userToSuspend -> {

			try {
				// load the user information
				UserDTO userDTO = this.userMapper
						.toDTO(this.ldapResourceClient.getUserByMatricule(userToSuspend.getCodePA()), false, false);
				String codePA = userDTO.getCodePA();

				// check if the auth user has the appropriate habilitation
				if (this.securityServiceUtils.isManagerOf(authUser, userDTO)) {

					// generate TR012 event with 2 notifications:
					// prepare notification params:
					// NOT023 to Managers:
					Entry<String, Map<String, String>> managerNotificationParams = entry(MANAGER_LABEL, Map.ofEntries(
							entry("suspendedUsercodePA", codePA), entry(CODEPARTNER_LABEL, userDTO.getCodePartner())));
					// NOT034 to concerned user:
					Entry<String, Map<String, String>> concernedNotificationParams = entry(CONCERNED,
							Map.of(CODEPA_LABEL, codePA));
					Event event012 = this.eventService.generateEvent("TR-012", authUser,
							Map.ofEntries(managerNotificationParams, concernedNotificationParams));

					event012.setUserTarget(codePA);

					// suspend User in LDAP
					this.ldapResourceClient.suspendUser(codePA);

					// set suspended by manager attribute to true
					UserLDAP userLDAP = UserLDAP.builder().codePA(codePA).suspendedByManager("TRUE").build();
					this.ldapResourceClient.updateUser(userLDAP);

					// publish event == send notification and save all traces (event, notification,
					// email ... ) in database
					// add event params
					event012.setParams(Map.of(USER_DTO, this.utilsMapper.serializeDTOAsString(userDTO)));
					this.applicationEventPublisher.publishEvent(event012);

					log.info("The user {} has been suspended correctly in LDAP", codePA);

				} else {
					// the auth user has not autority to suspend this user
					log.error("The user {} has no authority to suspend the user {} ", authenticatedUserId, codePA);
					throw new HappyClientException(Status.FORBIDDEN, FORBIDDEN_CODE,
							"You are not authorized to suspend the user");
				}

			} catch (HappyBusinessException e) {
				log.error(e.getMessage());
				if (e.getCode().endsWith("404")) {
					log.error("The user {} has not been found in LDAP Directory", userToSuspend.getCodePA());
					throw new HappyClientException(Status.NOT_FOUND, USER_NOT_FOUND_CODE,
							THE_USER + userToSuspend.getCodePA() + " has not been found in LDAP Directory");
				} else {
					log.error("An error has occured when searching the user {} : {}", userToSuspend.getCodePA(), e);
					throw e;
				}
			}

		});

	}

	public void reactivateUsers(List<UserDTO> usersToReactivate) {

		UserDTO authUser = this.securityServiceUtils.loadAuthenticatedUserFromContext();
		String authenticatedUserId = authUser.getCodePA();
		log.info(LOAD_USER_MSG, authenticatedUserId);

		// suspend Users
		usersToReactivate.forEach(userToReactivate -> {

			try {
				// load the user information
				UserDTO userDTO = this.userMapper
						.toDTO(this.ldapResourceClient.getUserByMatricule(userToReactivate.getCodePA()), false, false);
				String codePA = userDTO.getCodePA();

				// check if the auth user has the appropriate habilitation
				if (this.securityServiceUtils.isManagerOf(authUser, userDTO)) {

					// generate TR013 event with 2 notifications:
					// prepare notification params:
					// NOT024 to Managers:
					Entry<String, Map<String, String>> managerNotificationParams = entry(MANAGER_LABEL,
							Map.ofEntries(entry("reactivatedUsercodePA", codePA),
									entry(CODEPARTNER_LABEL, userDTO.getCodePartner())));
					// NOT008 to concerned user:
					Entry<String, Map<String, String>> concernedNotificationParams = entry(CONCERNED,
							Map.of(CODEPA_LABEL, codePA, "urlLoginPage", frontUrl));
					Event event013 = this.eventService.generateEvent("TR-013", authUser,
							Map.ofEntries(managerNotificationParams, concernedNotificationParams));
					event013.setUserTarget(codePA);

					// reactivate User in LDAP
					this.ldapResourceClient.reactivateUser(codePA);

					// set suspended by manager attribute to false
					UserLDAP userLDAP = UserLDAP.builder().codePA(codePA).suspendedByManager("FALSE").build();
					this.ldapResourceClient.updateUser(userLDAP);

					// add event params
					event013.setParams(Map.of(USER_DTO, this.utilsMapper.serializeDTOAsString(userDTO)));
					// publish event == send notification and save all traces (event, notification,
					// email ... ) in database
					this.applicationEventPublisher.publishEvent(event013);
					log.info("The user {} ahs been reactivated correctly in LDAP", codePA);

				} else {
					// the auth user has not autority to suspend this user
					log.error("The user {} has no authority to reactivate the user {} ", authenticatedUserId, codePA);
					throw new HappyClientException(Status.FORBIDDEN, FORBIDDEN_CODE,
							"You are not authorized to reactivate the user");
				}

			} catch (HappyBusinessException e) {
				log.error(e.getMessage());
				if (e.getCode().endsWith("404")) {
					log.error("The user {} has not been found in LDAP Directory", userToReactivate.getCodePA());
					throw new HappyClientException(Status.NOT_FOUND, USER_NOT_FOUND_CODE,
							THE_USER + userToReactivate.getCodePA() + " has not been found in LDAP Directory");
				} else {
					log.error("An error has occured when searching the user {} : {}", userToReactivate.getCodePA(), e);
					throw e;
				}
			}
		});

	}

	public UserDTO prepareUserForUpdate(UserDTO userDTO) {

		UserDTO authUser = this.securityServiceUtils.loadAuthenticatedUserFromContext();
		String authenticatedUserId = authUser.getCodePA();
		log.info(LOAD_USER_MSG, authenticatedUserId);

		Role authUserRole = authUser.getRole();

		String codePA = userDTO.getCodePA();

		// load the initial state of the user to update
		UserDTO userDtoInit = this.getUserByCodePAWithRoles(codePA)
				.orElseThrow(() -> new HappyClientException(Status.NOT_FOUND, "USER_NOT_FOUND",
						THE_USER + codePA + " didn't exist"));

		switch (authUserRole) {
		case GESTIONNAIRE: {
			// submit a modification's request

			// check if the auth user has the manager authorities over the submitted user
			if (!this.securityServiceUtils.isManagerOf(authUser, userDtoInit)
					&& !Objects.equals(authUser.getCodePA(), userDtoInit.getCodePA())) {
				log.error("Unauthorized !");
				throw new HappyClientException(Status.FORBIDDEN, FORBIDDEN_CODE,
						"You don't have the manager authorities");
			}

			// generate unique URL
			UniqueURL uniqueURL = UniqueURL.builder().context("users/confirm/habilitationModification")
					.token(UUID.randomUUID().toString()).valid(true).build();

			// params of the user notification, (personalTitle, nom, prenom ) already
			// populated by the event's generation mecanism
			Entry<String, String> urlConfirmModifuser = entry("urlConfirmModifuser", this.generateUniqueURL(uniqueURL));
			Entry<String, Map<String, String>> userParams = entry("user", Map.ofEntries(urlConfirmModifuser));

			// TR045 submit a confirmation to the auth user
			Event eventTR045 = this.eventService.generateEvent("TR-045", authUser, Map.ofEntries(userParams));
			eventTR045.setUserTarget(userDTO.getCodePA());
			Request request = eventTR045.getRequest();
			request.setUniqueURL(uniqueURL);
			uniqueURL.setRequest(request);
			request.setRecipient(authUser.getCodePA());

			try {
				Entry<String, String> userParamEntry = entry(USER_DTO, this.mapper.writeValueAsString(userDTO));
				request.setParams(Map.ofEntries(userParamEntry));
				eventTR045.setParams(Map.ofEntries(userParamEntry));
			} catch (JsonProcessingException e) {
				throw new HappyBusinessException(USER_JSON_ERROR_CODE, USER_JSON_ERROR_SHORTLIB, e);
			}

			// add event params
			Entry<String, String> oldUserDTO = entry("oldUserDTO", this.utilsMapper.serializeDTOAsString(userDtoInit));
			Entry<String, String> newUserDTO = entry("newUserDTO", this.utilsMapper.serializeDTOAsString(userDTO));
			eventTR045.setParams(Map.ofEntries(oldUserDTO, newUserDTO));

			this.applicationEventPublisher.publishEvent(eventTR045);

			log.info("generate the event [TR019] {}", eventTR045.getId());

			break;
		}
		default:
			log.error("Unauthorized !");
			throw new HappyClientException(Status.FORBIDDEN, FORBIDDEN_CODE,
					"You are not authorized to modify the user");
		}
		return userDTO;

	}

	public void addEditRemoveUserHabilitations(UserDTO oldUserDTO, UserDTO newUserDTO) {
		List<SmartConnectHabilitationDTO> oldSmartConnectHabilitationDTOs = oldUserDTO
				.getSmartConnectHabilitationDTOs();
		List<FrontalHabilitationDTO> oldFrontalHabilitationDTOs = oldUserDTO.getFrontalHabilitationDTOs();

		List<SmartConnectHabilitationDTO> newSmartConnectHabilitationDTOs = newUserDTO
				.getSmartConnectHabilitationDTOs();
		List<FrontalHabilitationDTO> newFrontalHabilitationDTOs = newUserDTO.getFrontalHabilitationDTOs();

		// extract role to add (SmartConnect Habilitation)
		newSmartConnectHabilitationDTOs.stream()
				.filter(newSch -> oldSmartConnectHabilitationDTOs.stream()
						.noneMatch(oldSch -> oldSch.getCodePartner().equals(newSch.getCodePartner())))
				.forEach(newSch -> {
					// add role to user (Smartconnect)
					this.addRemoveSmartConnectHabilitationForUser(oldUserDTO, newSch, "add");
				});

		// extract role to remove (Smartconnect)
		oldSmartConnectHabilitationDTOs.stream()
				.filter(schInit -> newSmartConnectHabilitationDTOs.stream()
						.noneMatch(schNew -> schNew.getCodePartner().equals(schInit.getCodePartner())))
				.forEach(oldSch -> {
					// remove role to user (Smartconnect)
					this.addRemoveSmartConnectHabilitationForUser(oldUserDTO, oldSch, REMOVE);
				});

		// extract role to add (Frontal Habilitation)
		newFrontalHabilitationDTOs.stream().filter(newFh -> oldFrontalHabilitationDTOs.stream()
				.noneMatch(oldFh -> oldFh.getFrontal().equals(newFh.getFrontal()))).forEach(newFh -> {
					// add role to user (Frontal)
					this.addRemoveFrontalHabilitationForUser(oldUserDTO.getCodePA(), newFh, "add");
					log.info("add role to user (Frontal) {} {}", newFh.getFrontal(), newFh.getHabilitation());
				});

		// extract role to remove (Frontal)
		oldFrontalHabilitationDTOs.stream()
				.filter(oldFh -> newFrontalHabilitationDTOs.stream()
						.noneMatch(newFh -> newFh.getFrontal().equals(oldFh.getFrontal())))
				.forEach(oldFh -> {
					// remove role to user (Frontal)
					this.addRemoveFrontalHabilitationForUser(oldUserDTO.getCodePA(), oldFh, REMOVE);
				});

		// extract role to update (Frontal)
		newFrontalHabilitationDTOs.stream()
				.filter(newFh -> oldFrontalHabilitationDTOs.stream()
						.anyMatch(oldFh -> oldFh.getFrontal().equals(newFh.getFrontal())
								&& !oldFh.getHabilitation().equals(newFh.getHabilitation())))
				.forEach(newFh -> {
					// update role to user (Frontal)
					oldFrontalHabilitationDTOs.stream().filter(oldFh -> oldFh.getFrontal().equals(newFh.getFrontal()))
							.findAny().ifPresent(oldFh -> this
									.addRemoveFrontalHabilitationForUser(oldUserDTO.getCodePA(), oldFh, REMOVE));
					this.addRemoveFrontalHabilitationForUser(oldUserDTO.getCodePA(), newFh, "add");
				});
	}

	public void updateUserFull(UserDTO userDTO) {
		UserDTO authUser = this.securityServiceUtils.loadAuthenticatedUserFromContext();
		if (Role.FORMATEUR == authUser.getRole() || Role.ADMIN == authUser.getRole() || Role.GESTIONNAIRE == authUser.getRole()) {
			// get the old user instance
			UserDTO oldUserDTO = this.getUserByCodePAWithRoles(userDTO.getCodePA())
					.orElseThrow(() -> new HappyClientException(Status.NOT_FOUND, "USER_NOT_FOUND",
							THE_USER + userDTO.getCodePA() + " has not been found"));

			// *** smar 283 begin
			// email removed
			if (userDTO.getEmail() != null && !userDTO.getEmail().isBlank()
					&& !userDTO.getEmail().equalsIgnoreCase(oldUserDTO.getEmail())) {
				this.addEmail(userDTO);

				// fix email error when generating the tr008 event
				oldUserDTO.setEmail(userDTO.getEmail());

			} else if ((userDTO.getEmail() == null || ("").equals(userDTO.getEmail()))
					&& (oldUserDTO.getEmail() != null || !("").equals(oldUserDTO.getEmail()))) {
				userDTO.setEmail("nomail@smartconnect.fr");
				this.updateUser(userDTO);
			} else {
				this.updateUser(userDTO);
			}
			// *** smar 283 End

			// update the habilitations
			this.addEditRemoveUserHabilitations(oldUserDTO, userDTO);
			log.info("Update the habilitations of the user {}", oldUserDTO.getCodePA());

			// partner changed
			if (!oldUserDTO.getCodePartner().equals(userDTO.getCodePartner())) {
				this.updateUserPartner(oldUserDTO, userDTO.getPartnerDTO());
				log.info("Update the partner of the user {} => {}", oldUserDTO.getCodePartner(),
						userDTO.getPartnerDTO().getCodePartner());

			}

			userDTO.formatInput();

			Event event042 = this.eventService.generateEvent("TR-042", authUser, Map.of());

			// add param event
			event042.setParams(Map.ofEntries(entry("oldUserDTO", this.utilsMapper.serializeDTOAsString(oldUserDTO)),
					entry("newUserDTO", this.utilsMapper.serializeDTOAsString(userDTO))));

		} else {
			throw new HappyClientException(Status.FORBIDDEN, "UPDATE USER AUTH",
					"NOT AUTHORIZED TO EXECUTE THIS METHOD");
		}
	}

	public void updateUserPartner(UserDTO userDTO, PartnerDTO partnerDTO) {
		String oldCodePartner = userDTO.getCodePartner();
		String newCodePartner = partnerDTO.getCodePartner();
		String codePA = userDTO.getCodePA();

		if (oldCodePartner.equals(newCodePartner)) {
			log.warn("The user {} has already been affected to this partner {}", userDTO.getCodePA(), oldCodePartner);
		}

		String oldPartnerGroupName = "SG_SMARTCONNECT_Apporteurs_" + oldCodePartner;
		// remove the user from the old partner group
		this.ldapResourceClient.removeMember(oldPartnerGroupName, codePA);
		log.info("Remove user {} from  {}", codePA, oldCodePartner);

		String newPartnerGroupName = "SG_SMARTCONNECT_Apporteurs_" + newCodePartner;
		// remove the user from the old partner group
		this.ldapResourceClient.addMember(newPartnerGroupName, codePA);
		log.info("Add user {} to  {}", codePA, newCodePartner);

		// update codePartner ldap attribute
		UserLDAP userLDAP = UserLDAP.builder().codePA(codePA).codePartner(newCodePartner)
				.codePartnerParent(newCodePartner).build();
		this.ldapResourceClient.updateUser(userLDAP);

	}

	public void addRemoveFrontalHabilitationForUser(String codePA, FrontalHabilitationDTO frontalHabilitationDTO,
			String action) {
		UserDTO userDTOauth = this.securityServiceUtils.loadAuthenticatedUserFromContext();
		switch (action) {
		case "add": {
			String frontaHabilitationGroupName = String.join("_", "SG", frontalHabilitationDTO.getFrontal(),
					frontalHabilitationDTO.getHabilitation() + groupUtils.returnSuffix(
							frontalHabilitationDTO.getFrontal(), frontalHabilitationDTO.getHabilitation()));
			this.ldapResourceClient.addMember(frontaHabilitationGroupName, codePA);
			log.info("add role to user (Frontal) {} {}", frontalHabilitationDTO.getFrontal(),
					frontalHabilitationDTO.getHabilitation());
			Event event014 = this.eventService.generateEvent("TR-014", userDTOauth, Map.of());
			if(event014 != null) {
				event014.setUserTarget(codePA);
				Request reqEvent014 = event014.getRequest();
				Entry<String, String> reqEvent014Profil = entry("addedProfil", frontalHabilitationDTO.getHabilitation());
				Entry<String, String> reqEvent014Frontal = entry(FRONTAL_LABEL, frontalHabilitationDTO.getFrontal());
				reqEvent014.setParams(Map.ofEntries(reqEvent014Profil, reqEvent014Frontal));
				// add event params
				UserLDAP userLDAP = this.ldapResourceClient.getUserByMatricule(codePA);
				UserDTO userDTO = this.userMapper.toDTO(userLDAP, false, false);
				event014.setParams(Map.ofEntries(entry(USER_DTO, this.utilsMapper.serializeDTOAsString(userDTO)),
						entry(FRONTAL_HABILITATION_DTO, this.utilsMapper.serializeDTOAsString(frontalHabilitationDTO))));
				this.applicationEventPublisher.publishEvent(event014);
			}
			break;
		}
		case REMOVE: {
			String frontaHabilitationGroupName = String.join("_", "SG", frontalHabilitationDTO.getFrontal(),
					frontalHabilitationDTO.getHabilitation() + groupUtils.returnSuffix(
							frontalHabilitationDTO.getFrontal(), frontalHabilitationDTO.getHabilitation()));
			// The format is : SG_frontalName_Habiliations
			this.ldapResourceClient.removeMember(frontaHabilitationGroupName, codePA);
			log.info("remove role to user (Frontal) {} {}", frontalHabilitationDTO.getFrontal(),
					frontalHabilitationDTO.getHabilitation());
			Event event015 = this.eventService.generateEvent("TR-015", userDTOauth, Map.of());
			if(event015 != null) {
				event015.setUserTarget(codePA);
				Request reqEvent015 = event015.getRequest();
				Entry<String, String> reqEvent015Profil = entry("removedProfil", frontalHabilitationDTO.getHabilitation());
				Entry<String, String> reqEvent015Frontal = entry(FRONTAL_LABEL, frontalHabilitationDTO.getFrontal());
				reqEvent015.setParams(Map.ofEntries(reqEvent015Profil, reqEvent015Frontal));

				// add event params
				UserLDAP userLDAP = this.ldapResourceClient.getUserByMatricule(codePA);
				UserDTO userDTO = this.userMapper.toDTO(userLDAP, false, false);
				event015.setParams(Map.ofEntries(entry(USER_DTO, this.utilsMapper.serializeDTOAsString(userDTO)),
						entry(FRONTAL_HABILITATION_DTO, this.utilsMapper.serializeDTOAsString(frontalHabilitationDTO))));
				this.applicationEventPublisher.publishEvent(event015);
			}
			break;
		}
		default: {
			log.error("Operation {} not supported", action);
			break;
		}
		}

	}

	public void addRemoveSmartConnectHabilitationForUser(UserDTO userDTO,
			SmartConnectHabilitationDTO smartConnectHabilitationDTO, String action) {
		UserDTO authUserDTO = this.securityServiceUtils.loadAuthenticatedUserFromContext();
		switch (action) {
		case "add": {
			String smartConnectHabilitationGroupName = String.join("_", "SG", SMARTCONNECT_LABEL,
					smartConnectHabilitationDTO.getHabilitation() + "s", smartConnectHabilitationDTO.getCodePartner());
			this.ldapResourceClient.addMember(smartConnectHabilitationGroupName, userDTO.getCodePA());
			log.info("add role to user (Smartconnect) {} {}", smartConnectHabilitationDTO.getCodePartner(),
					smartConnectHabilitationDTO.getHabilitation());
			Event event008 = this.eventService.generateEvent(TR008, authUserDTO, Map.of());
			event008.setUserTarget(userDTO.getCodePA());
			if (smartConnectHabilitationDTO.getHabilitation() == Role.GESTIONNAIRE) {
				// not011
				Notification not011 = Notification.builder().technicalId("NOT-011").event(event008)
						.recipient(userDTO.getCodePA()).build();
				event008.getNotifications().add(not011);
				not011.generateNotificationId();

				if (userDTO.getEmail() == null || userDTO.getEmail().isBlank()) {
					log.warn("No mail address was found for the user : " + userDTO.getCodePA());
				}
				Map<String, String> mailManagerParams = new HashMap<>();
				mailManagerParams.put(PERSONALTITLE_LABEL, userDTO.getPersonalTitle());
				mailManagerParams.put("nom", userDTO.getNom() + " " + userDTO.getPrenom());
				mailManagerParams.put(POINTOFSALE_LABEL, smartConnectHabilitationDTO.getPointOfSales());
				mailManagerParams.put("frontalApplication", "");
				EmailTrace emailTrace = EmailTrace.builder().notification(not011).recipient(userDTO.getEmail())
						.params(mailManagerParams).status(EmailStateEnum.PENDIND).build();
				not011.setEmailTrace(emailTrace);
				log.info("generate not011 {} for event014 {} [ADD GESTIONNAIRE]", not011.getId(), event008.getId());
				Entry<String, String> reqEvent008POS = entry(POINTOFSALE_LABEL,
						smartConnectHabilitationDTO.getCodePartner());
				event008.getRequest().setParams(Map.ofEntries(reqEvent008POS));
			}

			// add params event
			event008.setParams(Map.ofEntries(
					entry(SMARTCONNECT_HABILITATION_DTO,
							this.utilsMapper.serializeDTOAsString(smartConnectHabilitationDTO)),
					entry(USER_DTO, this.utilsMapper.serializeDTOAsString(userDTO))));

			this.applicationEventPublisher.publishEvent(event008);
			break;
		}
		case REMOVE: {
			String smartConnectHabilitationGroupName = String.join("_", "SG", SMARTCONNECT_LABEL,
					smartConnectHabilitationDTO.getHabilitation() + "s", smartConnectHabilitationDTO.getCodePartner());
			this.ldapResourceClient.removeMember(smartConnectHabilitationGroupName, userDTO.getCodePA());
			log.info("remove role to user (Smartconnect) {} {}", smartConnectHabilitationDTO.getCodePartner(),
					smartConnectHabilitationDTO.getHabilitation());
			Event event048 = this.eventService.generateEvent("TR-048", authUserDTO, Map.of());
			event048.setUserTarget(userDTO.getCodePA());
			if (smartConnectHabilitationDTO.getHabilitation() == Role.GESTIONNAIRE) {
				// not011
				Notification not039 = Notification.builder().technicalId("NOT-039").event(event048)
						.recipient(userDTO.getCodePA()).build();
				event048.getNotifications().add(not039);
				not039.generateNotificationId();

				if (userDTO.getEmail() == null || userDTO.getEmail().isBlank()) {
					log.warn("No mail address was found for the user : " + userDTO.getCodePA());
				}
				Map<String, String> mailManagerParams = new HashMap<>();
				mailManagerParams.put(PERSONALTITLE_LABEL, userDTO.getPersonalTitle());
				mailManagerParams.put("nom", userDTO.getNom() + " " + userDTO.getPrenom());
				mailManagerParams.put(POINTOFSALE_LABEL, smartConnectHabilitationDTO.getCodePartner());
				mailManagerParams.put("frontalApplication", "");
				EmailTrace emailTrace = EmailTrace.builder().notification(not039).recipient(userDTO.getEmail())
						.params(mailManagerParams).status(EmailStateEnum.PENDIND).build();
				not039.setEmailTrace(emailTrace);
				log.info("generate not011 {} for event014 {} [ADD GESTIONNAIRE]", not039.getId(), event048.getId());
				Entry<String, String> reqEvent048POS = entry(POINTOFSALE_LABEL,
						smartConnectHabilitationDTO.getCodePartner());
				event048.getRequest().setParams(Map.ofEntries(reqEvent048POS));
			}

			// add event params
			event048.setParams(Map.ofEntries(
					entry("smartconnectHabilitationDTO",
							this.utilsMapper.serializeDTOAsString(smartConnectHabilitationDTO)),
					entry(USER_DTO, this.utilsMapper.serializeDTOAsString(userDTO))));

			this.applicationEventPublisher.publishEvent(event048);
			break;
		}
		default: {
			log.error("Operation {} not supported", action);
			break;
		}
		}

	}

	public void resetPasswordOfManagedUser(UserDTO userDTO) {
		UserDTO authUser = this.securityServiceUtils.loadAuthenticatedUserFromContext();
		String authUserId = authUser.getCodePA();
		if (this.securityServiceUtils.isManagerOf(authUser, userDTO)) {
			String newPassword = userDTO.getPassword();
			this.ldapResourceClient.resetPassword(userDTO.getCodePA(), newPassword);
			log.info("changing {} user password", userDTO.getCodePA());
			Event eventTR051 = this.eventService.generateEvent("TR-051", userDTO, Map.ofEntries());
			Request request = eventTR051.getRequest();
			String nomGest = authUser.getPersonalTitle() + " " + authUser.getPrenom() + " " + authUser.getNom();
			Map<String, String> requestParams = Map.ofEntries(entry("gestionnaire", nomGest));
			request.setParams(requestParams);

			// add event params
			eventTR051.setParams(Map.ofEntries(entry(USER_DTO, this.utilsMapper.serializeDTOAsString(userDTO)),
					entry("authUserDTO", this.utilsMapper.serializeDTOAsString(authUser))));

			log.info("generate event TR051 {}", eventTR051.getId());
			this.applicationEventPublisher.publishEvent(eventTR051);
		} else {
			throw new HappyBusinessException("NOT AUTHORIZED",
					"the user " + authUserId + " is not authorized to reset " + userDTO.getCodePA() + " user pswd");
		}
	}

	public void monitorUsers() {
		// TODO Auto-generated method stub

	}

}
