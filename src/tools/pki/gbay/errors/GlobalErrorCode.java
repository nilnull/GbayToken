package tools.pki.gbay.errors;


/**
 *
 * <h1>List of all errors</h1>
 * <h2>Error types<h2>
 * Success (XX0), Not found (XX1), Invalid "What is invalid" (XX2), Error and FAIL "WHAT" (XX3), Warnings (XX4), Measurable Fails (XX5),Invalid "Why is Invalid" (XX6),FAIL ERROR "WHY" XX7	
 *<h2>Categories</h2>
 * Transaction (0XX) , File 1XX , Entity 2XX , Pin 3XX , Requirment 4XX , Certificate 5XX , Key 6XX , Signature 7XX , USER 9XX , Token 10XX
 *
 */


public enum GlobalErrorCode {
	TXN_SUCCESS	(0),
	TXN_NOT_FOUND	(1),
	TXN_INVALID	(2),
	TXN_FAIL(3),
	TXN_WARNING(4),
	TXN_INVALID_LENGTH(5),
	TXN_EXPECTED_FAILED(13),
	FILE_NOT_FOUND(101),
	FILE_INVALID(102),
	FILE_IO_ERROR(103),
	FILE_EXEED_SIZE(105),
	FILE_INCORRECT_FORMAT(106),
	FILE_FAILED_DEPENDENCY(107),
	FILE_CANNOT_OPEN(112),
	ENTITY_NOT_FOUND(201),
	ENTITY_INCORRECT_FORMAT(202),
	ENTITY_FAIL(203),
	ENTITY_UPDATE_NEEDED(204),
	ENTITY_INVALID_LENGTH(205),
	ENTITY_CLASS_NOT_FOUND(211),
	ENTITY_RETRY_EXCEED_MAX(215),
	PIN_NEEDED(301),
	PIN_INVALID_FORMAT(302),
	PIN_INCORRECT(303),
	PIN_LOCKED(304),
	PIN_INVALID_LENGTH(305),
	SOPIN_DIFFER_SERVER(307),
	REQ_NOT_FOUND(401),
	REQ_NOT_ACCEPTABLE(402),
	REQ_PRECONDITION_FAILED(403),
	REQ_PARAMETER_WARNING(404),
	REQ_UNAUTHORIZED(406),
	REQ_METHOD_NOT_ALLOWED(407),
	REQ_SERVICE_NOT_FOUND(411),
	REQ_LOGIN_FAILED(413),
	REQ_FORBIDDEN(416),
	REQ_LOGIN_NEEDED(417),
	REQ_USER_NOT_FOUND(421),
	REQ_PARAMETER_FAILED(423),
	REQ_ALREADY_LOGED_IN(433),
	CERT_NOT_FOUND(501),
	CERT_INVALID_FORMAT(502),
	CERT_VERIFY_FAILED(503),
	CERT_EXIST(504),
	CERT_NOT_RENEWED(506),
	CERT_CRL_NOT_FOUND(511),
	CERT_INVALID_ALGORITHM(512),
	CERT_EMPTY_DB(514),
	CERT_EXPIRED(516),
	CERT_CRL_NOT_SET(521),
	CERT_INVALID_PADDING(522),
	CERT_REVOKED(526),
	CERT_ISSUER_NOT_FOUND(531),
	CERT_INVALID_SIGNATURE(532),
	CERT_NOT_YET_VALID(536),
	CERT_ISSUER_NOT_SET(541),
	CERT_INVALID_CA_SIGNATURE(542),
	CERT_IS_SELF_SIGNED(552),
	KEY_NOT_FOUND(601),
	KEY_INVALID(602),
	KEY_GENERATION_FAILED(603),
	KEY_DUPLICATED(606),
	KEY_PROVIDER_NOT_FOUND(611),
	KEY_NOT_INSTALLED(621),
	SIG_VERIFY_PASS(700),
	SIG_NOT_FOUND(701),
	SIG_INVALID(702),
	SIG_VERIFY_FAIL(703),
	SIG_VERIFY_ERROR(713),
	SIG_AUTH_FAIL(723),
	SIG_GENERATION_FAIL(733),
	USER_NOT_FOUND(901),
	USER_INVALID(902),
	USER_FAIL(903),
	USER_ALREADY_LOGGED_IN(904),
	TOKEN_NOT_INSIDE(1001),
	TOKEN_NOT_DETECTED(1002),
	TOKEN_SIGN_FAIL(1003),
	TOKEN_KEY_NOT_MATCHED(1004),
	TOKEN_INVALID_LENGTH(1005),
	TOKEN_FAILED_ALOCATE_MEMORY(1007),
	TOKEN_OBJECT_NOT_FOUND(1011),
	TOKEN_INVALID_LOGIN_TYPE(1012),
	TOKEN_ERR_LOAD_LIBRARY(1013),
	TOKEN_MORE_THAN_ONE(1014),
	TOKEN_SIG_INVALID_LENGTH(1015),
	TOKEN_GET_ATTRIBUTE_FAIL(1017),
	TOKEN_OPERATION_CANCEL(1021),
	TOKEN_INVALID_SESSION_ID(1022),
	TOKEN_INIT_SIGN_FAIL(1023),
	TOKEN_PKI_NOTINITIALISE(1024),
	TOKEN_INVALID_SLOT(1025),
	TOKEN_SET_PUBLICKEY_FAIL(1027),
	TOKEN_ADD_ENTRY_NAME_FAIL(1033),
	TOKEN_GET_SUBJECT_NAME_FAIL(1037),
	TOKEN_SET_CERT_VERSION_FAIL(1043),
	TOKEN_HASH_FAILED(1053);

	public final int id;

	private GlobalErrorCode(int i) {
		id = i;
	}

	public boolean Compare(int i) {
		return id == i;
	}

	public static String getName(int _id) {
		return GlobalErrorCode.GetError(_id).name();
	}

	public static GlobalErrorCode GetError(int _id) {
		
		GlobalErrorCode[] As = GlobalErrorCode.values();
		for (int i = 0; i < As.length; i++) {
			if (As[i].Compare(_id)){
			System.err.println(_id +" found");
				return As[i];
			}
		}
		return GlobalErrorCode.TXN_SUCCESS;
	}
	
	public  int getID(){
		return id;
	}

}