const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  WidthType, AlignmentType, HeadingLevel, PageBreak, BorderStyle,
  ShadingType, Footer, PageNumber, ImageRun,
} = require('docx');
const fs = require('fs');
const JSZip = require('jszip');

const navy = '17365D';
const border = { style: BorderStyle.SINGLE, size: 6, color: '808080' };
const cellBorders = { top: border, bottom: border, left: border, right: border };
const base = { font: 'Times New Roman', size: 24 };
const para = (text, opts = {}) => new Paragraph({
  alignment: opts.alignment || AlignmentType.JUSTIFIED,
  spacing: { line: 360, after: opts.after ?? 120, before: opts.before ?? 0 },
  indent: opts.indent ? { firstLine: 720 } : undefined,
  children: Array.isArray(text) ? text : [new TextRun({ text, ...base, ...(opts.bold ? { bold: true } : {}), ...(opts.italics ? { italics: true } : {}) })],
});
const heading = (text, level = 1) => new Paragraph({
  text, heading: level === 1 ? HeadingLevel.HEADING_1 : level === 2 ? HeadingLevel.HEADING_2 : HeadingLevel.HEADING_3,
  alignment: level === 1 ? AlignmentType.CENTER : AlignmentType.LEFT,
  spacing: { before: level === 1 ? 240 : 180, after: 120 },
  run: { font: 'Times New Roman', bold: true, size: level === 1 ? 28 : 26, color: navy },
});
const caption = (text, type = 'Table') => new Paragraph({
  alignment: AlignmentType.CENTER, spacing: { before: 100, after: 180 },
  children: [new TextRun({ text: `${type} ${text}`, ...base, bold: true, italics: true })],
});
const list = (text, n) => new Paragraph({
  alignment: AlignmentType.JUSTIFIED, spacing: { line: 360, after: 80 },
  indent: { left: 720, hanging: 360 },
  children: [new TextRun({ text: `${n}. `, ...base, bold: true }), new TextRun({ text, ...base })],
});
const cell = (text, header = false, align = AlignmentType.LEFT) => new TableCell({
  borders: cellBorders, shading: header ? { type: ShadingType.CLEAR, fill: 'D9EAF7' } : undefined,
  verticalAlign: 'center',
  children: [new Paragraph({ alignment: align, spacing: { after: 60, before: 60 }, children: [new TextRun({ text: String(text), ...base, bold: header })] })],
});
const table = (headers, rows, widths) => new Table({
  width: { size: 100, type: WidthType.PERCENTAGE },
  rows: [new TableRow({ children: headers.map((h, i) => cell(h, true, AlignmentType.CENTER)) }), ...rows.map(r => new TableRow({ children: r.map((x, i) => cell(x, false, i === 0 ? AlignmentType.LEFT : AlignmentType.LEFT)) }))],
});
const diagram = (rows) => new Table({
  width: { size: 100, type: WidthType.PERCENTAGE },
  rows: rows.map(r => new TableRow({ children: r.map(x => cell(x, false, AlignmentType.CENTER)) })),
});
const visual = (captionText, lines, height = 150) => {
  const width = 620;
  const lineHeight = Math.max(30, Math.floor((height - 20) / lines.length));
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}"><rect width="100%" height="100%" fill="#ffffff"/><defs><marker id="a" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 Z" fill="#17365d"/></marker></defs>${lines.map((l, i) => { const y = 10 + i * lineHeight; return `<rect x="20" y="${y}" width="580" height="${lineHeight - 8}" rx="7" fill="#eaf3f8" stroke="#17365d"/><text x="310" y="${y + Math.floor(lineHeight / 2) + 5}" font-family="Times New Roman" font-size="15" text-anchor="middle" fill="#17365d">${l.replace(/&/g, '&amp;')}</text>${i < lines.length - 1 ? `<line x1="310" y1="${y + lineHeight - 8}" x2="310" y2="${y + lineHeight + 2}" stroke="#17365d" stroke-width="2" marker-end="url(#a)"/>` : ''}`; }).join('')}</svg>`;
  const fallbackPng = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScL0igAAAABJRU5ErkJggg==', 'base64');
  return [new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 120, after: 60 }, children: [new ImageRun({ data: Buffer.from(svg), type: 'svg', fallback: { data: fallbackPng, type: 'png' }, transformation: { width: 460, height: Math.round(460 * height / width) } })] }), caption(captionText, 'Figure')];
};

const content = [];
const add = (...items) => content.push(...items);
const chapter = (title) => { if (content.length) add(new Paragraph({ children: [new PageBreak()] })); add(heading(title, 1)); };

// Cover page
add(
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 260 }, children: [new TextRun({ text: 'THE CATHOLIC UNIVERSITY OF EASTERN AFRICA', ...base, bold: true, size: 28 })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 120 }, children: [new TextRun({ text: 'SCHOOL OF SCIENCE', ...base, bold: true, size: 26 })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 500 }, children: [new TextRun({ text: 'DEPARTMENT OF COMPUTER SCIENCE', ...base, bold: true, size: 26 })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 360 }, children: [new TextRun({ text: 'SCI 400: RESEARCH PROJECT', ...base, bold: true })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 360 }, children: [new TextRun({ text: 'PROJECT PROPOSAL FOR FINAL YEAR STUDY IN\nBACHELOR OF SCIENCE IN COMPUTER SCIENCE', ...base, bold: true })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 220 }, children: [new TextRun({ text: 'BY', ...base, bold: true })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 440 }, children: [new TextRun({ text: 'MOSES MARANGA (1050896)', ...base, bold: true })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 150 }, children: [new TextRun({ text: 'PROJECT TITLE', ...base, bold: true })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 520 }, children: [new TextRun({ text: 'DESIGN AND IMPLEMENTATION OF A WEB-BASED STUDENT MARKETPLACE', ...base, bold: true, size: 26 })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: 'DATE: JULY, 2026', ...base, bold: true })] }),
  new Paragraph({ children: [new PageBreak()] }),
  heading('TABLE OF CONTENTS', 1),
  ...['Terms and Abbreviations','CHAPTER ONE: INTRODUCTION','CHAPTER TWO: REVIEW OF RELATED WORK','CHAPTER THREE: RESEARCH METHODOLOGY','CHAPTER FOUR: SYSTEM ANALYSIS','REFERENCES','APPENDICES'].map(x => para(x, { alignment: AlignmentType.LEFT })),
  new Paragraph({ children: [new PageBreak()] }),
  heading('TERMS AND ABBREVIATIONS', 1),
  ...['API — Application Programming Interface','CRUD — Create, Read, Update and Delete','CUEA — Catholic University of Eastern Africa','DFD — Data Flow Diagram','ERD — Entity Relationship Diagram','ICT — Information and Communication Technology','M-Pesa — Mobile money service operated by Safaricom','SQL — Structured Query Language','UI/UX — User Interface / User Experience','WWW — World Wide Web'].map(x => para(x, { alignment: AlignmentType.LEFT }))
);

chapter('CHAPTER ONE: INTRODUCTION');
add(heading('1.1 Background', 2),
  para('Information and Communication Technology (ICT) refers to digital technologies, computer systems, software applications, telecommunications and internet-based services used to create, store, process and exchange information. ICT improves communication, data management and access to services, and has become an important driver of productivity, innovation and social development.', { indent: true }),
  para('The growth of affordable smartphones, internet connectivity, cloud services and digital payments has transformed commerce in both developed and developing countries. In retail, e-commerce platforms reduce the distance between buyers and sellers. In Kenya, mobile money has shown how digital services can make transactions more accessible and convenient (Mas & Radcliffe, 2010).', { indent: true }),
  para('Within universities, students regularly exchange textbooks, electronic gadgets, clothing, event tickets and services such as tutoring. These transactions are commonly conducted through WhatsApp groups, notice boards and word of mouth. Although these channels are familiar, they are fragmented, difficult to search, and provide few safeguards against fraud or misrepresentation.', { indent: true }),
  para('This study proposes UniMarket, a web-based student marketplace for the CUEA community. The platform will centralise listings and enable students to discover goods and services, communicate with sellers, make offers, maintain wishlists and provide ratings and reviews in a more structured environment.', { indent: true }),
  heading('1.2 Problem Statement', 2),
  para('CUEA students do not have a dedicated and trustworthy digital platform through which they can buy, sell and exchange goods and services within their university community. As a result, students depend on WhatsApp groups, physical notice boards and word of mouth, which have limited reach, poor searchability and no consistent way to organise listings. Consequently, willing buyers and sellers often fail to find one another, and students spend unnecessary time searching for relevant items or customers.', { indent: true }),
  para('The informal channels also provide limited accountability. A buyer cannot readily verify a seller’s reputation, compare listings systematically, keep a structured record of offers, or report suspicious activity through an institutional channel. These weaknesses expose students to possible fraud and misrepresentation and discourage participation in peer-to-peer trade. This research therefore seeks to design and implement UniMarket, a web-based marketplace that provides organised listings, user accounts, in-platform communication, offer management, ratings and administrative oversight for the CUEA community.', { indent: true }),
  heading('1.3 Aim of Research', 2), para('The aim of this research is to design and implement a web-based student marketplace platform for the CUEA community that enables students to list, discover and trade goods and services in a secure and structured digital environment.', { indent: true }),
  heading('1.4 Objectives', 2),
  list('To review literature on peer-to-peer marketplace platforms, web application security and student-centred digital commerce in order to identify best practices and research gaps.', 1),
  list('To collect and analyse requirements from CUEA students and administrators using questionnaires and interviews.', 2),
  list('To analyse the current informal student trading environment and identify its processes, users, strengths and weaknesses.', 3),
  list('To design the proposed UniMarket system, including its database, user interfaces, process logic and system architecture.', 4),
  list('To implement the UniMarket web platform using Python, SQLite and HTML, CSS and JavaScript.', 5),
  list('To test the system and evaluate its functional correctness, usability, security and performance.', 6),
  heading('1.5 Justification', 2),
  para('A dedicated student marketplace is justified because digital marketplaces lower search costs and reduce information asymmetry between buyers and sellers (Einav, Farronato, & Levin, 2016). By bringing campus trade into one searchable environment, UniMarket can improve the visibility of student-owned goods and services and make peer-to-peer transactions more efficient.', { indent: true }),
  para('The platform is also justified by the need for trust. Reputation systems have been shown to support transactions among strangers by making previous interactions visible (Resnick & Zeckhauser, 2002). UniMarket will support ratings, reviews and listing reports, providing information and accountability that is generally absent from informal channels.', { indent: true }),
  heading('1.6 Scope', 2),
  para('Target Organisation: This study is a case study of the Catholic University of Eastern Africa (CUEA).', { indent: true }),
  para('Target Users: Students are the primary buyers and sellers. Administrators moderate reports and manage platform content.', { indent: true }),
  para('Features to be Implemented: Registration and authentication, listings for goods and services, search and categories, listing management, messaging, offers, wishlists, ratings and reviews, reporting and an administration dashboard.', { indent: true }),
  para('Timeline and Exclusions: Research and development will run from March 2026 to September 2026. Native mobile applications, payment-gateway processing, delivery logistics and deployment to multiple institutions are outside this phase of the project.', { indent: true }),
  heading('1.7 Research Organization', 2),
  para('This proposal is organised into four chapters. Chapter One introduces the study. Chapter Two reviews related work and identifies the research gap. Chapter Three presents the methodology for the study. Chapter Four analyses the current student trading system, identifies requirements and presents its process logic. The final project report will add chapters on system design, implementation, testing, deployment and conclusions.', { indent: true })
);

chapter('CHAPTER TWO: REVIEW OF RELATED WORK');
add(heading('2.1 Chapter Introduction', 2), para('This chapter reviews literature and related systems relevant to a web-based university marketplace. It traces the development of online marketplaces, evaluates selected systems from global to local contexts, considers emerging trends and identifies the gap addressed by UniMarket.', { indent: true }),
  heading('2.2 History of Online Marketplaces', 2),
  para('Online marketplaces emerged during the commercialisation of the internet in the mid-1990s. eBay demonstrated that individuals could exchange goods with strangers using auction listings and feedback, while Amazon expanded from an online bookstore into a large e-commerce marketplace (Laudon & Traver, 2021). Improvements in broadband, smartphones and secure payment services later made marketplaces available to a wider population.', { indent: true }),
  para('In Kenya, the spread of mobile money and smartphone use supported the development of local digital commerce. Jumia, Jiji and Facebook Marketplace offer channels for buying and selling goods, while WhatsApp groups continue to support community-based trade. However, these channels are not designed around the verification, moderation and small-scale peer trading needs of one university community.', { indent: true }),
  heading('2.3 Review of Related Systems', 2),
  table(['System', 'How it works and key features', 'Strengths', 'Weaknesses'], [
    ['eBay', 'Users list goods at auction or fixed prices; buyers purchase or bid; feedback follows a transaction.', 'Mature reputation system, search and dispute resolution.', 'Fees and global orientation make it less suitable for small campus trade.'],
    ['Amazon Marketplace', 'Third-party sellers list products alongside Amazon’s catalogue; payment and fulfilment options are integrated.', 'Strong search, reviews and logistics.', 'Complex onboarding and limited fit for informal student-to-student trade.'],
    ['Jumia Kenya', 'Vendors list products, customers order online, and local delivery and payment options are available.', 'Kenyan market awareness and local payment support.', 'Commission and delivery model suit formal vendors more than student peers.'],
    ['Jiji Kenya', 'Individuals publish classified advertisements and negotiate directly with interested buyers.', 'Easy local listing and broad category coverage.', 'Limited community verification and variable trust between users.'],
    ['Facebook Marketplace', 'Users browse local listings through Facebook and communicate using Messenger.', 'Large existing user base and simple communication.', 'Listings are mixed with social media and lack campus-specific oversight.'],
  ]), caption('2.1: Comparison of Related Marketplace Systems'),
  heading('2.4 Emerging Trends and Patterns', 2),
  heading('2.4.1 Machine Learning', 3), para('Machine learning supports personalised recommendations, search ranking and anomaly detection. In a marketplace, it can learn from browsing and listing behaviour to suggest relevant items and flag unusual activity. These capabilities are future enhancements for UniMarket because the first version will focus on reliable core transactions.', { indent: true }),
  ...visual('2.1: Machine-Learning Recommendation Process', ['Student browsing and listing activity', 'Recommendation and anomaly-detection model', 'Relevant item suggestions and fraud alerts']),
  heading('2.4.2 Artificial Intelligence', 3), para('Artificial intelligence can support automated customer assistance, content moderation and image-based classification. Natural-language tools can assist users in writing descriptions, while moderation can help identify prohibited or misleading content. Human administrative review remains important where an automated result may be inaccurate.', { indent: true }),
  ...visual('2.2: AI-Supported Marketplace Moderation', ['Listing text and image submitted', 'AI checks category, prohibited content and clarity', 'Administrator review or safe publication']),
  heading('2.4.3 Electronic Payments', 3), para('Electronic payments make online commerce more convenient by reducing cash-handling risk. M-Pesa is particularly relevant in Kenya because it is widely used by students. Payment processing is not included in this project phase; instead, the system will support transparent communication and offer management while parties agree on a safe payment method.', { indent: true }),
  ...visual('2.3: Electronic-Payment Transaction Concept', ['Buyer agrees on item and price', 'Buyer uses agreed payment channel', 'Seller confirms payment and hands over item']),
  heading('2.4.4 Blockchain Technology', 3), para('Blockchain can provide tamper-resistant transaction records and programmable escrow through smart contracts. It may strengthen trust in future marketplace systems, although scalability, user experience and implementation cost make it unsuitable for the first UniMarket version (Nakamoto, 2008).', { indent: true }),
  ...visual('2.4: Blockchain Escrow Concept', ['Buyer and seller agree transaction terms', 'Smart contract holds transaction record', 'Release after confirmed handover']),
  heading('2.5 Research Gap', 2),
  para('The reviewed systems show that marketplaces can provide searchable listings, communication and reputation signals, but they do not fully address the context of a CUEA student community. Global and regional platforms are designed for broad commercial audiences rather than small, campus-based peer transactions. Informal channels remain convenient but offer weak search, fragmented listings and limited reporting or accountability.', { indent: true }),
  para('UniMarket addresses this gap by consolidating student goods and service listings in one platform designed for CUEA users. Its proposed combination of structured categories, user accounts, offers, messaging, ratings, reporting and administrator oversight will support a clearer and more accountable trading experience without claiming to replace payment processors or logistics providers.', { indent: true }),
  heading('2.6 Chapter Summary', 2), para('This chapter reviewed the growth of online marketplaces, compared five related systems and examined relevant technological trends. The review established the need for a university-focused platform that supports organised, accountable peer-to-peer trade. The next chapter presents the methodology used in the study.', { indent: true })
);

chapter('CHAPTER THREE: RESEARCH METHODOLOGY');
add(heading('3.1 Chapter Introduction', 2), para('This chapter describes the methods that will be used to gather information, specify requirements, analyse the current system, design the proposed system, implement the platform, test it and prepare it for deployment. The methods are selected to combine quantitative evidence from students with qualitative evidence from key institutional stakeholders.', { indent: true }),
  heading('3.2 Methodology for Literature Review', 2), para('A systematic literature review will be conducted using scholarly books, journals, conference proceedings and credible technical sources. Most sources will be published between 2015 and 2026, except foundational works needed for historical context. Search terms will include online marketplace platforms, peer-to-peer e-commerce, student marketplace systems, web application security, database design and digital commerce in East Africa. Google Scholar, IEEE Xplore, ACM Digital Library and SpringerLink will be used. Sources will be assessed for relevance, credibility, recency and connection to the study objectives.', { indent: true }),
  heading('3.3 Methodology for Requirements Specification', 2),
  heading('3.3.1 Questionnaires', 3), para('A structured questionnaire will be administered to approximately fifty CUEA students drawn from different faculties and years of study. It will collect data on current trading habits, common channels, challenges, preferred features and trust expectations. Questionnaires are selected because they collect comparable information from many respondents efficiently and permit frequency and percentage analysis.', { indent: true }),
  heading('3.3.2 Interviews', 3), para('Semi-structured interviews will be held with five to eight key informants, including student representatives, an ICT officer and an administrator. Open-ended questions will explore institutional concerns, likely moderation needs and current student-trading challenges. Interviews complement questionnaires by providing detail and allowing follow-up questions.', { indent: true }),
  heading('3.4 Methodology for System Analysis', 2), para('Structured systems analysis will be used to understand the current informal trading environment. It models actors, activities, information flows, decisions and weaknesses before a solution is designed. The approach has been chosen because marketplace activity is transaction-oriented and involves clear flows of listing information, enquiries, offers and feedback.', { indent: true }),
  heading('3.4.1 Data Flow Diagrams', 3), para('A data flow diagram (DFD) is a graphical representation of how data moves between external entities, processes and data stores. A context diagram will be used to establish the system boundary, while lower-level DFDs will show how listing, enquiry and transaction information moves in the current system. This makes missing controls and manual hand-offs visible.', { indent: true }),
  heading('3.5 Methodology for System Design', 2),
  heading('3.5.1 Proposed-System DFDs', 3), para('Context, Level 1 and selected Level 2 DFDs will be developed for the proposed system. They will represent how the platform receives, stores and shares data among students and administrators. DFDs are chosen because they convert requirements into a shared, understandable process model.', { indent: true }),
  heading('3.5.2 Flowcharts', 3), para('Flowcharts are diagrams that show the sequence of actions and decisions in a process. They will be used to model registration, listing publication, offers and review submission. The information represented includes start and end points, user actions, validation decisions and outputs. Flowcharts are selected because they clarify procedural logic for both technical and non-technical readers.', { indent: true }),
  heading('3.5.3 User Interface Design', 3), para('High-fidelity interface prototypes will be prepared in Figma for the landing page, listing browse page, listing details, seller profile, inbox, offers, wishlist and administrator dashboard. Prototyping is chosen because it enables students to review navigation and screen content before coding, reducing costly changes during implementation.', { indent: true }),
  heading('3.5.4 Database Design', 3), para('An Entity Relationship Diagram (ERD) and data dictionary will describe entities, attributes, primary keys, foreign keys and relationships. Core entities will include User, Listing, Message, Offer, Wishlist, Review and Report. These artefacts are chosen to ensure data is structured consistently, supports the required processes and can be normalised to Third Normal Form in Chapter Four.', { indent: true }),
  heading('3.6 Methodology for System Implementation', 2),
  para('UniMarket will be implemented as a web application. Python 3 will be used for the backend because its readable syntax and standard library support the development of a small HTTP server and application logic. HTML5, CSS3 and JavaScript will be used on the frontend because they are the standard technologies of the web and provide direct control of page structure, presentation and interaction. SQLite will store data because it is lightweight, requires no separate database server and is appropriate for a single-server academic prototype. Passwords will be hashed and sessions protected using secure cookies; uploaded images will be validated before storage.', { indent: true }),
  heading('3.7 Methodology for System Testing', 2),
  para('Testing will follow a written test plan assembled from the functional and non-functional requirements. The plan will identify the feature to test, preconditions, steps, expected result, actual result and pass or fail status. Test cases will cover the most important user journeys: account registration and login, listing creation and editing, search, messaging, offers, wishlists, reviews, reporting and administration. These tests are selected because they map directly to user requirements and the areas most likely to affect trust and usability.', { indent: true }),
  para('Approximately twenty student participants and two administrators will be invited to complete guided usability tasks during the pilot. Their feedback will be recorded through observation and short follow-up questions, prioritised by severity and incorporated into revisions. Basic security checks will verify input validation, authentication restrictions, session handling and file-upload controls. Performance checks will observe response times for common browsing and listing actions under normal pilot use.', { indent: true }),
  heading('3.8 Methodology for System Deployment', 2), para('A phased deployment approach will be used. First, the system will be introduced to a pilot group of twenty students and two administrators for two weeks. Feedback and defects will be reviewed before a broader CUEA rollout. The system will begin with an empty database, so data migration is not required. Short user orientation material will be prepared to explain registration, listing, reporting and safe trading practices.', { indent: true }),
  heading('3.9 Chapter Summary', 2), para('This chapter has outlined the planned methods for literature review, requirements collection, analysis, design, implementation, testing and deployment. The following chapter applies the analysis method to the current informal student marketplace and derives requirements for UniMarket.', { indent: true })
);

chapter('CHAPTER FOUR: SYSTEM ANALYSIS');
add(heading('4.1 Chapter Introduction', 2), para('This chapter analyses the current system used by CUEA students to buy and sell goods and services. The analysis focuses on the informal channels currently used, their actors, information flows, strengths and limitations. It also presents the feasibility study, requirements analysis, current-system users and process-logic models that guide the proposed UniMarket system.', { indent: true }),
  heading('4.2 Description of the Current System', 2),
  para('The current student marketplace is informal and distributed across WhatsApp groups, Facebook Marketplace, physical notice boards and personal referrals. A student who wants to sell an item writes a message or posts a photograph, price and contact details. Interested students discover the post through a group, a friend or a notice board and contact the seller directly. Negotiation normally occurs through private messages, telephone calls or face-to-face meetings.', { indent: true }),
  para('There is no central database of listings, no standard form for item details, no institutional verification of traders and no consistent record of offers or completed transactions. Posts may be deleted, buried by new messages or duplicated across groups. Trust is based largely on personal familiarity, screenshots, chat history or informal recommendations. When a dispute occurs, students have no defined platform process for reporting it or tracking its resolution.', { indent: true }),
  para('In the current process, advertising is done through WhatsApp, Facebook, notice boards or word of mouth; the seller shares a photograph, brief description, price and contact details. Searching is done by scrolling through group messages, posts, personal contacts or a physical board. Negotiation takes place through private chat, calls or face-to-face discussions, and payment and collection are arranged privately. If a problem arises, a student may inform a group administrator or a university office, but there is no formal reporting workflow or shared evidence trail.', { indent: true }),
  heading('4.3 Strengths of the Current System', 2),
  list('It is familiar to students because WhatsApp and social media are already widely used.', 1),
  list('It has low immediate cost because students can post messages without subscribing to a new service.', 2),
  list('It allows direct and fast communication between a buyer and a seller.', 3),
  list('Personal networks can create a basic level of social trust among students who know each other.', 4),
  list('It is flexible: students can advertise many kinds of goods and services without a formal listing process.', 5),
  heading('4.4 Weaknesses of the Current System', 2),
  list('Listings are fragmented across several groups and channels, making them difficult to discover and compare.', 1),
  list('Posts lack a standard format, so important information such as item condition, price and availability may be missing.', 2),
  list('There is no university-specific account verification or dependable reputation mechanism.', 3),
  list('Buyers and sellers cannot manage offers, wishlists or transaction status in one place.', 4),
  list('Group messages are quickly buried, leading to duplicate enquiries and missed opportunities.', 5),
  list('There is no formal process for reporting suspicious listings, maintaining evidence or resolving disputes.', 6),
  list('Administrators cannot monitor trends, reported content or user activity through a dedicated dashboard.', 7),
  heading('4.5 Feasibility Study and Conclusion', 2),
  para('Technical feasibility: The proposed platform can be built with Python, SQLite, HTML, CSS and JavaScript on a standard computer or web server. Authentication, listings, search, messaging and reviews are technically achievable with the selected tools.', { indent: true }),
  para('Operational feasibility: Students already trade online and are familiar with web and mobile interfaces. A focused orientation and clear moderation rules will support adoption.', { indent: true }),
  para('Economic feasibility: The academic prototype uses free and open-source development tools. The main costs are internet access, printing, stationery and modest hosting if public deployment is required.', { indent: true }),
  para('Legal and ethical feasibility: The system will store account and listing information. It will therefore require consent, minimal data collection, password protection, acceptable-use rules and appropriate handling of reports.', { indent: true }),
  para('Schedule feasibility: The work can be completed within the March–September 2026 project period through phased research, development, testing and documentation.', { indent: true }),
  para('The feasibility study concludes that UniMarket is viable as an academic web-based prototype. The project uses accessible tools, addresses a familiar student need and can be delivered within the planned timeframe. Its success depends on clear requirements, secure implementation, active moderation and pilot feedback.', { indent: true }),
  heading('4.6 Requirements Analysis', 2),
  heading('4.6.1 Functional Requirements', 3),
  list('FR-01: The system shall allow students to register, log in and log out securely.', 1),
  list('FR-02: The system shall allow authenticated users to create, view, edit and delete their listings.', 2),
  list('FR-03: The system shall allow users to browse, search and filter listings by category, keyword and availability.', 3),
  list('FR-04: The system shall allow a buyer to send an enquiry or message to a seller about a listing.', 4),
  list('FR-05: The system shall allow a buyer to submit an offer and allow the seller to accept, reject or counter it.', 5),
  list('FR-06: The system shall allow users to save listings in a wishlist.', 6),
  list('FR-07: The system shall allow users to rate and review completed interactions.', 7),
  list('FR-08: The system shall allow users to report suspicious listings or inappropriate behaviour.', 8),
  list('FR-09: The system shall allow an administrator to review reports and manage users or listings when necessary.', 9),
  list('FR-10: The system shall provide a user profile showing public seller information and ratings.', 10),
  heading('4.6.2 Non-Functional Requirements', 3),
  list('NFR-01 Usability: Core tasks shall be understandable to a first-time student user through clear navigation, labels and feedback messages.', 1),
  list('NFR-02 Security: Passwords shall be hashed; authenticated pages shall be protected; user inputs and uploads shall be validated.', 2),
  list('NFR-03 Performance: Common pages such as browse, search and listing details should load promptly under normal pilot use.', 3),
  list('NFR-04 Reliability: The system shall validate required data and handle errors without corrupting stored records.', 4),
  list('NFR-05 Compatibility: The user interface shall work in current desktop and mobile web browsers.', 5),
  list('NFR-06 Maintainability: Source code and database structures shall use clear names and separation of responsibilities to support future updates.', 6),
  list('NFR-07 Privacy: Only information necessary for account and listing functions shall be collected and displayed according to user permissions.', 7),
  heading('4.6.3 Data Requirements', 3),
  para('User data will include a user identifier, name, email address, password hash, role, profile details and rating summary. Listing data will include a listing identifier, seller identifier, title, description, category, price, condition, status, image path and date created. Message data will include sender, recipient, related listing, content, timestamp and read status. Offer data will record the listing, buyer, amount, status and date created.', { indent: true }),
  para('Wishlist data will link a user to a saved listing. Review data will record the reviewer, reviewed user, rating, comment and date created. Report data will record the reporter, relevant listing, reason, status, administrator note and date created. These records provide the information required for account management, listings, communication, negotiation, reputation and moderation.', { indent: true }),
  heading('4.6.4 Data Normalisation', 3),
  para('The proposed database will be normalised to Third Normal Form (3NF). First Normal Form ensures that each field contains one atomic value and that repeating groups are removed. Second Normal Form ensures that non-key attributes depend on the whole primary key. Third Normal Form removes transitive dependencies so that non-key attributes depend only on the key. Separating users, listings, messages, offers, reviews and reports reduces duplication and helps preserve data integrity.', { indent: true }),
  heading('4.7 Current System Users and Their Roles', 2),
  list('Student seller: advertises a good or service, responds to enquiries and negotiates an exchange using item descriptions, photographs, prices, contact details and availability information.', 1),
  list('Student buyer: searches for items, contacts sellers, negotiates and agrees on payment and collection using enquiries, offers and personal contact details.', 2),
  list('Group administrator or class representative: may approve posts, share notices or intervene informally when conflict arises using group rules, notices and complaints.', 3),
  list('University administration: has no direct system role today but may receive serious complaints through ordinary institutional channels.', 4),
  heading('4.8 Process Logic Design', 2),
  heading('4.8.1 Current-System Context Diagram', 3),
  para('The context diagram treats the informal marketplace as one process and shows the information that crosses its boundary. It identifies the key external entities and confirms that the present process relies on personal communication rather than a central information store.', { indent: true }),
  ...visual('4.1: Context Diagram of the Current Informal Student Marketplace', ['Student seller: listing details and contact', 'Informal trading channels: WhatsApp, notice boards and referrals', 'Student buyer: enquiries, offers and feedback', 'Group administrator / university: complaints or concerns'], 190),
  heading('4.8.2 Current-System Level 1 DFD', 3),
  para('The Level 1 DFD decomposes the current informal marketplace into its main processes. It shows that information is created, circulated and negotiated through separate channels, without a shared database or formal control point.', { indent: true }),
  ...visual('4.2: Level 1 DFD of the Current Informal Student Marketplace', ['1.0 Post advertisement to informal channel', '2.0 Buyer searches posts and sends enquiry', '3.0 Buyer and seller negotiate through private chat or call', '4.0 Informal complaint is raised to a group administrator'], 190),
  heading('4.8.3 Current-System Flowchart: Buying an Item', 3),
  para('The following flowchart models the normal buyer journey in the current system. It captures search, direct contact, negotiation and the decision to proceed. The absence of a formal transaction record or dispute route is visible after the exchange.', { indent: true }),
  ...visual('4.3: Flowchart for Buying an Item in the Current System', ['Start: buyer searches groups and contacts', 'Find a suitable listing?', 'Contact seller and negotiate price and collection', 'Agree? Arrange payment and private handover', 'End: no central record, review or structured report'], 220),
  heading('4.9 Chapter Summary', 2),
  para('This chapter analysed the current informal student trading environment at CUEA. Although the current channels are familiar and low-cost, they are fragmented and lack structured search, records, verification, reporting and administrative oversight. The feasibility study found the proposed system viable, while the functional, non-functional and data requirements define the basis for UniMarket’s design and implementation. The context diagram, DFD and flowchart demonstrate the current information flows and the need for a centralised platform.', { indent: true })
);

chapter('REFERENCES');
[
  'Aggarwal, C. C. (2020). Recommender systems: The textbook. Springer.',
  'Communications Authority of Kenya. (2023). Sector statistics report. https://www.ca.go.ke/',
  'Einav, L., Farronato, C., & Levin, J. (2016). Peer-to-peer markets. Annual Review of Economics, 8(1), 615–635. https://doi.org/10.1146/annurev-economics-080315-015334',
  'Laudon, K. C., & Traver, C. G. (2021). E-commerce 2021–2022: Business, technology, society. Pearson.',
  'Mas, I., & Radcliffe, D. (2010). Mobile payments go viral: M-PESA in Kenya. World Bank.',
  'Nakamoto, S. (2008). Bitcoin: A peer-to-peer electronic cash system. https://bitcoin.org/bitcoin.pdf',
  'OWASP Foundation. (2021). OWASP Top Ten. https://owasp.org/www-project-top-ten/',
  'Resnick, P., & Zeckhauser, R. (2002). Trust among strangers in internet transactions: Empirical analysis of eBay’s reputation system. The Economics of the Internet and E-Commerce, 11, 127–157.',
  'Russell, S., & Norvig, P. (2021). Artificial intelligence: A modern approach (4th ed.). Pearson.',
  'Suri, T., & Jack, W. (2021). The long-run poverty and gender impacts of mobile money. Science, 354(6317), 1288–1292.',
].forEach(x => add(para(x, { indent: true })));

chapter('APPENDICES');
add(heading('Appendix A: Project Schedule', 2),
  table(['Activity', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep'], [
    ['Proposal refinement and literature review', '●', '●', '', '', '', '', ''],
    ['Requirements collection and analysis', '', '●', '●', '', '', '', ''],
    ['System design and interface prototyping', '', '', '●', '●', '', '', ''],
    ['Implementation of core modules', '', '', '', '●', '●', '', ''],
    ['Testing, pilot feedback and revisions', '', '', '', '', '●', '●', ''],
    ['Documentation, final report and submission', '', '', '', '', '', '●', '●'],
  ]), caption('A.1: Project Schedule (March–September 2026)'),
  heading('Appendix B: Project Budget', 2),
  table(['Budget Item', 'Estimated Cost (KES)', 'Notes'], [
    ['Internet access for research and development', '6,000', 'Estimated over the project period.'],
    ['Printing and binding', '1,200', 'Proposal and final report copies.'],
    ['Stationery', '500', 'Questionnaires, notes and related materials.'],
    ['Pilot hosting / deployment contingency', '2,000', 'Only if public hosting is required.'],
    ['Total', '9,700', 'Personal laptop and domain registration are excluded because they are not project expenditure.'],
  ]), caption('B.1: Project Budget'),
  heading('Appendix C: Sample Questionnaire', 2),
  para('Dear Participant,', { alignment: AlignmentType.LEFT }),
  para('My name is Moses Maranga (1050896), a Bachelor of Science in Computer Science student at the Catholic University of Eastern Africa. I am conducting a final-year research project titled “Design and Implementation of a Web-Based Student Marketplace.” This questionnaire seeks to understand student trading practices and preferences. Your participation is voluntary. The information you provide will be used only for academic research, reported in summary form and handled confidentially. Please do not write your name on this questionnaire.', { indent: true }),
  para('Instructions: Tick or circle the answer that best represents your view. Where more than one answer applies, follow the instruction given.', { indent: true }),
  heading('Section A: Background Information', 3),
  list('What is your faculty? [ ] Science  [ ] Commerce  [ ] Arts  [ ] Education  [ ] Other', 1),
  list('What is your year of study? [ ] Year 1  [ ] Year 2  [ ] Year 3  [ ] Year 4', 2),
  heading('Section B: Current Trading Habits', 3),
  list('Have you ever bought or sold items with fellow students? [ ] Yes  [ ] No', 3),
  list('Which channels do you use to trade with fellow students? (Tick all that apply) [ ] WhatsApp [ ] Facebook [ ] Notice boards [ ] Word of mouth [ ] Other', 4),
  list('How satisfied are you with your current trading methods? [ ] Very satisfied [ ] Satisfied [ ] Neutral [ ] Dissatisfied [ ] Very dissatisfied', 5),
  heading('Section C: Platform Feature Preferences', 3),
  list('How important is a ratings and reviews system for sellers? [ ] Very important [ ] Important [ ] Neutral [ ] Not important', 6),
  list('Would you use a price-negotiation feature? [ ] Yes [ ] Maybe [ ] No', 7),
  list('Which categories would you most like to buy or sell? Rank from 1–5: [ ] Textbooks [ ] Electronics [ ] Clothes [ ] Event tickets [ ] Services', 8),
  list('What would make you trust a student marketplace? [ ] Verified accounts [ ] Ratings and reviews [ ] Administrator reporting [ ] Clear item photos [ ] Other', 9),
  heading('Appendix D: Sample Interview Questions', 2),
  para('Target interviewees: student representatives, ICT officer and university administration representative.', { indent: true }),
  list('What are the most common challenges students face when trading goods or services with each other on campus?', 1),
  list('What features would be essential in a digital student marketplace platform?', 2),
  list('What concerns would you have about a marketplace operating within the university community?', 3),
  list('What role should university administration play in oversight, moderation or dispute handling?', 4),
  list('What would encourage or discourage students from using the platform?', 5),
  list('Are there existing institutional systems or processes that the platform should consider?', 6),
);

const doc = new Document({
  styles: { default: { document: { run: { font: 'Times New Roman', size: 24 }, paragraph: { spacing: { line: 360, after: 120 } } } } },
  sections: [{
    properties: { page: { margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 } } },
    footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: 'Page ', ...base }), new TextRun({ children: [PageNumber.CURRENT], ...base })] })] }) },
    children: content,
  }],
});

Packer.toBuffer(doc).then(async buffer => {
  // docx creates an empty comments part by default. Remove it and its links so
  // the delivered document has no comment metadata at all.
  const zip = await JSZip.loadAsync(buffer);
  zip.remove('word/comments.xml');
  const contentTypes = await zip.file('[Content_Types].xml').async('string');
  zip.file('[Content_Types].xml', contentTypes.replace(/<Override[^>]*PartName="\/word\/comments\.xml"[^>]*\/>/g, ''));
  const relPath = 'word/_rels/document.xml.rels';
  const rels = await zip.file(relPath).async('string');
  zip.file(relPath, rels.replace(/<Relationship[^>]*Type="[^"]*\/comments"[^>]*\/>/g, ''));
  fs.writeFileSync('UniMarket_Revised_Proposal_with_Chapter_4.docx', await zip.generateAsync({ type: 'nodebuffer' }));
});
