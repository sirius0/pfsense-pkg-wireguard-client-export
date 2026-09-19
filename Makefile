PORTNAME=	pfSense-pkg-WireGuard-ClientExport
PORTVERSION=	0.1.0.b2
CATEGORIES=	net
MASTER_SITES=	# empty
DISTFILES=	# empty
EXTRACT_ONLY=	# empty

MAINTAINER=	sirius0@users.noreply.github.com
COMMENT=	Minimal WireGuard remote-access client provisioning for pfSense

LICENSE=	APACHE20

RUN_DEPENDS=	pfSense-pkg-WireGuard=0.2.13_4:net/pfSense-pkg-WireGuard

NO_ARCH=	yes
NO_BUILD=	yes
NO_MTREE=	yes

SUB_FILES=	pkg-install pkg-deinstall
SUB_LIST=	PORTNAME=${PORTNAME}

do-extract:
	${MKDIR} ${WRKSRC}

do-install:
	${MKDIR} ${STAGEDIR}/etc/inc/priv
	${MKDIR} ${STAGEDIR}${PREFIX}/pkg/wgclientexport
	${MKDIR} ${STAGEDIR}${PREFIX}/www/wgclientexport/js
	${MKDIR} ${STAGEDIR}${DATADIR}

	${INSTALL_DATA} ${FILESDIR}/etc/inc/priv/wgclientexport.priv.inc \
		${STAGEDIR}/etc/inc/priv
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/wgclientexport.xml \
		${STAGEDIR}${PREFIX}/pkg
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/wgclientexport/*.inc \
		${STAGEDIR}${PREFIX}/pkg/wgclientexport
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/wgclientexport/*.php \
		${STAGEDIR}${PREFIX}/www/wgclientexport
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/wgclientexport/js/*.js \
		${STAGEDIR}${PREFIX}/www/wgclientexport/js
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/share/${PORTNAME}/info.xml \
		${STAGEDIR}${DATADIR}
	${INSTALL_DATA} ${.CURDIR}/LICENSE \
		${STAGEDIR}${DATADIR}
	${INSTALL_DATA} ${.CURDIR}/THIRD_PARTY_NOTICES.md \
		${STAGEDIR}${DATADIR}

	@${REINPLACE_CMD} -i '' -e "s|%%PKGVERSION%%|${PKGVERSION}|" \
		${STAGEDIR}${DATADIR}/info.xml \
		${STAGEDIR}${PREFIX}/pkg/wgclientexport.xml
	@${REINPLACE_CMD} -i '' -e "s|%%WGCLIENTEXPORT_VERSION%%|${PKGVERSION}|" \
		${STAGEDIR}${PREFIX}/pkg/wgclientexport/bootstrap.inc

.include <bsd.port.mk>
