# scanner.py
import socket
import ssl
import http.client
import urllib.parse
import re
import datetime
import base64
from typing import Callable, List
import concurrent.futures
import threading

class DomainScanner:
    def __init__(self, domain: str):
        """Initialize the domain scanner with the target domain."""
        domain = re.sub(r'https?://|:[0-9]+', '', domain.lower()).split('/')[0]
        self.domain = domain
        self.log_message: Callable[[str], None] = print
        self.timeout = 3  # seconds for network operations
        self.stop_event = None  # Will be set by the app
        
    def should_stop(self):
        """Check if scanning should stop."""
        return self.stop_event and self.stop_event.is_set()

    def port_check(self, port: int) -> bool:
        """Check if a specific port is open on the target domain."""
        if self.should_stop():
            return False
            
        try:
            address = socket.gethostbyname(self.domain)
            with socket.create_connection((address, port), timeout=self.timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, socket.gaierror):
            return False
        except Exception as e:
            self.log_message(f"  ! Port {port} check failed: {str(e)}")
            return False

    def port_scan(self):
        """Scan for common open ports on the target domain."""
        if self.should_stop():
            return
            
        services = {
            20: 'FTP (Data)', 21: 'FTP (Control)', 22: 'SSH', 23: 'Telnet',
            25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 5900: 'VNC', 8080: 'HTTP Proxy',
            8443: 'HTTPS Alt', 9000: 'PHP-FPM', 27017: 'MongoDB'
        }
        
        self.log_message("\n[+] Performing Port Scan...\n")
        try:
            address = socket.gethostbyname(self.domain)
            open_ports = []
            
            # Use thread pool for faster scanning
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                future_to_port = {
                    executor.submit(self.port_check, port): port 
                    for port in services.keys()
                }
                
                for future in concurrent.futures.as_completed(future_to_port):
                    if self.should_stop():
                        executor.shutdown(wait=False)
                        return
                        
                    port = future_to_port[future]
                    try:
                        if future.result():
                            open_ports.append(port)
                            self.log_message(f"  - Port {port} is OPEN (Service: {services[port]})")
                    except Exception as e:
                        self.log_message(f"  ! Port {port} scan error: {str(e)}")
            
            if not open_ports:
                self.log_message("  - No Open Ports Detected.")
                
        except socket.gaierror:
            self.log_message("  ! Could not resolve domain name")
        except Exception as e:
            self.log_message(f"  ! Port scan failed: {str(e)}")

    def dns_enumeration(self):
        """Enumerate common subdomains of the target domain."""
        if self.should_stop():
            return
            
        subdomains = [
            'www', 'mail', 'webmail', 'smtp', 'pop', 'pop3', 'imap', 'ftp', 'ssh', 'dns', 
            'ns', 'ns1', 'ns2', 'ns3', 'ns4', 'mx', 'mx1', 'mx2', 'mx3', 'cdn', 'cdn1',
            'cdn2', 'cdn3', 'static', 'assets', 'media', 'images', 'img', 'files', 'uploads',
            'download', 'downloads', 'backup', 'backups', 'db', 'database', 'sql', 'mysql',
            'postgres', 'mongo', 'redis', 'elasticsearch', 'solr', 'ldap', 'vpn', 'proxy',
            'gateway', 'router', 'firewall', 'loadbalancer', 'lb', 'dev', 'dev1', 'dev2',
            'test', 'test1', 'test2', 'stage', 'staging', 'prod', 'production', 'beta',
            'alpha', 'demo', 'sandbox', 'qa', 'uat', 'preprod', 'pre-prod', 'ci', 'jenkins',
            'build', 'deploy', 'git', 'svn', 'repo', 'repository', 'registry', 'docker',
            'k8s', 'kubernetes', 'swarm', 'cloud', 'aws', 'azure', 'gcp', 'digitalocean',
            'linode', 'vultr', 'rackspace', 'heroku', 'openshift', 'cloudfront', 's3',
            'storage', 'bucket', 'blob', 'logs', 'log', 'monitor', 'monitoring', 'grafana',
            'prometheus', 'kibana', 'splunk', 'newrelic', 'datadog', 'status', 'health',
            'ping', 'uptime', 'alert', 'alerts', 'ops', 'operations', 'admin', 'administrator',
            'root', 'superuser', 'sysadmin', 'webadmin', 'control', 'manager', 'management',
            'cpanel', 'whm', 'plesk', 'webmin', 'directadmin', 'vesta', 'virtualmin',
            'phpmyadmin', 'adminer', 'roundcube', 'squirrelmail', 'horde', 'zimbra',
            'exchange', 'owa', 'activesync', 'autodiscover', 'lync', 'skype', 'teams',
            'sharepoint', 'portal', 'intranet', 'extranet', 'remote', 'vdi', 'citrix',
            'vmware', 'vsphere', 'esxi', 'hyperv', 'xen', 'kvm', 'openstack', 'openshift',
            
            # Common services
            'api', 'api1', 'api2', 'api3', 'rest', 'graphql', 'soap', 'rpc', 'grpc',
            'websocket', 'ws', 'wss', 'auth', 'authentication', 'oauth', 'oauth2', 'sso',
            'login', 'logout', 'register', 'signup', 'signin', 'account', 'accounts',
            'user', 'users', 'profile', 'profiles', 'member', 'members', 'customer',
            'customers', 'client', 'clients', 'partner', 'partners', 'vendor', 'vendors',
            'supplier', 'suppliers', 'employee', 'employees', 'staff', 'hr', 'payroll',
            'finance', 'accounting', 'billing', 'invoice', 'invoices', 'payment',
            'payments', 'checkout', 'cart', 'shop', 'store', 'ecommerce', 'pos',
            'inventory', 'warehouse', 'shipping', 'delivery', 'order', 'orders',
            'ticket', 'tickets', 'support', 'help', 'helpdesk', 'service', 'services',
            'contact', 'contacts', 'feedback', 'survey', 'surveys', 'poll', 'polls',
            'forum', 'forums', 'discussion', 'discussions', 'chat', 'messaging',
            'message', 'mail', 'email', 'newsletter', 'blog', 'blogs', 'news', 'newsroom',
            'press', 'media', 'events', 'event', 'calendar', 'schedule', 'booking',
            'reservation', 'reservations', 'appointment', 'appointments', 'meeting',
            'meetings', 'conference', 'conferences', 'webinar', 'webinars', 'training',
            'learn', 'learning', 'education', 'academy', 'university', 'school',
            'college', 'course', 'courses', 'lesson', 'lessons', 'tutorial', 'tutorials',
            'docs', 'documentation', 'wiki', 'knowledgebase', 'kb', 'faq', 'faqs',
            'guide', 'guides', 'manual', 'manuals', 'helpcenter', 'supportcenter',
            'community', 'communities', 'social', 'network', 'networking', 'connect',
            'discover', 'explore', 'find', 'search', 'discover', 'directory', 'browse',
            'explorer', 'explore', 'map', 'maps', 'location', 'locations', 'geo',
            'geolocation', 'tracking', 'track', 'gps', 'navigation', 'weather',
            'forecast', 'time', 'clock', 'date', 'calendar', 'scheduler', 'planner',
            'organizer', 'todo', 'tasks', 'notes', 'notepad', 'editor', 'editors',
            'ide', 'studio', 'code', 'source', 'sources', 'src', 'bin', 'build',
            'dist', 'release', 'releases', 'version', 'versions', 'patch', 'patches',
            'update', 'updates', 'upgrade', 'upgrades', 'install', 'installation',
            'setup', 'config', 'configuration', 'settings', 'preferences', 'options',
            'properties', 'env', 'environment', 'variables', 'secrets', 'keys',
            'credentials', 'password', 'passwords', 'security', 'secure', 'auth',
            'authentication', 'authorization', 'permission', 'permissions', 'role',
            'roles', 'policy', 'policies', 'rules', 'regulation', 'regulations',
            'compliance', 'audit', 'auditing', 'log', 'logs', 'history', 'record',
            'records', 'archive', 'archives', 'backup', 'backups', 'restore',
            'recovery', 'disaster', 'failover', 'redundancy', 'replication',
            'sync', 'synchronization', 'cluster', 'clustering', 'loadbalancer',
            'loadbalancing', 'scaling', 'scale', 'performance', 'optimization',
            'cache', 'caching', 'cdn', 'content', 'contents', 'asset', 'assets',
            'resource', 'resources', 'static', 'public', 'private', 'protected',
            'secure', 'internal', 'external', 'development', 'test', 'testing',
            'qa', 'staging', 'preprod', 'production', 'prod', 'live', 'canary',
            'blue', 'green', 'ab', 'experiment', 'experimental', 'research', 'lab',
            'labs', 'sandbox', 'playground', 'demo', 'demonstration', 'example',
            'examples', 'sample', 'samples', 'template', 'templates', 'boilerplate',
            'scaffold', 'scaffolding', 'framework', 'frameworks', 'library',
            'libraries', 'module', 'modules', 'package', 'packages', 'plugin',
            'plugins', 'extension', 'extensions', 'addon', 'addons', 'widget',
            'widgets', 'component', 'components', 'service', 'services', 'microservice',
            'microservices', 'api', 'apis', 'rest', 'graphql', 'grpc', 'soap',
            'websocket', 'ws', 'wss', 'rpc', 'message', 'messages', 'queue',
            'queues', 'event', 'events', 'stream', 'streaming', 'pubsub', 'bus',
            'broker', 'topic', 'topics', 'channel', 'channels', 'notification',
            'notifications', 'alert', 'alerts', 'monitor', 'monitoring', 'metrics',
            'analytics', 'analysis', 'report', 'reports', 'dashboard', 'dashboards',
            'visualization', 'visualizations', 'chart', 'charts', 'graph', 'graphs',
            'diagram', 'diagrams', 'map', 'maps', 'geo', 'geolocation', 'location',
            'locations', 'tracking', 'track', 'gps', 'navigation', 'direction',
            'directions', 'route', 'routes', 'path', 'paths', 'waypoint', 'waypoints',
            'destination', 'destinations', 'origin', 'origins', 'departure',
            'departures', 'arrival', 'arrivals', 'schedule', 'schedules', 'timetable',
            'timetables', 'calendar', 'calendars', 'agenda', 'agendas', 'planner',
            'planners', 'organizer', 'organizers', 'todo', 'todos', 'task', 'tasks',
            'checklist', 'checklists', 'note', 'notes', 'notepad', 'notepads',
            'document', 'documents', 'file', 'files', 'folder', 'folders', 'directory',
            'directories', 'archive', 'archives', 'backup', 'backups', 'snapshot',
            'snapshots', 'image', 'images', 'photo', 'photos', 'picture', 'pictures',
            'gallery', 'galleries', 'album', 'albums', 'video', 'videos', 'movie',
            'movies', 'clip', 'clips', 'stream', 'streaming', 'live', 'broadcast',
            'broadcasting', 'tv', 'television', 'radio', 'podcast', 'podcasts',
            'music', 'songs', 'audio', 'sound', 'sounds', 'voice', 'voices', 'speech',
            'recognition', 'synthesis', 'transcription', 'translation', 'language',
            'languages', 'locale', 'locales', 'international', 'global', 'world',
            'country', 'countries', 'region', 'regions', 'state', 'states', 'city',
            'cities', 'town', 'towns', 'village', 'villages', 'address', 'addresses',
            'location', 'locations', 'place', 'places', 'venue', 'venues', 'site',
            'sites', 'property', 'properties', 'realestate', 'housing', 'home',
            'homes', 'house', 'houses', 'apartment', 'apartments', 'condo', 'condos',
            'building', 'buildings', 'office', 'offices', 'workplace', 'workplaces',
            'company', 'companies', 'business', 'businesses', 'enterprise',
            'enterprises', 'organization', 'organizations', 'institution',
            'institutions', 'school', 'schools', 'university', 'universities',
            'college', 'colleges', 'academy', 'academies', 'institute', 'institutes',
            'education', 'educational', 'learning', 'teach', 'teaching', 'teacher',
            'teachers', 'student', 'students', 'class', 'classes', 'course', 'courses',
            'lesson', 'lessons', 'tutorial', 'tutorials', 'guide', 'guides', 'manual',
            'manuals', 'documentation', 'docs', 'wiki', 'wikis', 'knowledgebase',
            'kb', 'faq', 'faqs', 'help', 'helps', 'support', 'supports', 'service',
            'services', 'customer', 'customers', 'client', 'clients', 'user', 'users',
            'account', 'accounts', 'profile', 'profiles', 'member', 'members',
            'community', 'communities', 'social', 'network', 'networks', 'connect',
            'connection', 'connections', 'friend', 'friends', 'follower', 'followers',
            'following', 'message', 'messages', 'chat', 'chats', 'conversation',
            'conversations', 'discussion', 'discussions', 'forum', 'forums', 'board',
            'boards', 'group', 'groups', 'team', 'teams', 'project', 'projects',
            'task', 'tasks', 'issue', 'issues', 'bug', 'bugs', 'ticket', 'tickets',
            'request', 'requests', 'feedback', 'feedbacks', 'review', 'reviews',
            'rating', 'ratings', 'vote', 'votes', 'poll', 'polls', 'survey',
            'surveys', 'quiz', 'quizzes', 'test', 'tests', 'exam', 'exams',
            'assessment', 'assessments', 'evaluation', 'evaluations', 'grade',
            'grades', 'score', 'scores', 'result', 'results', 'report', 'reports',
            'analysis', 'analytics', 'statistic', 'statistics', 'data', 'dataset',
            'datasets', 'database', 'databases', 'db', 'dbs', 'table', 'tables',
            'row', 'rows', 'column', 'columns', 'field', 'fields', 'record',
            'records', 'entry', 'entries', 'item', 'items', 'object', 'objects',
            'entity', 'entities', 'model', 'models', 'schema', 'schemas', 'type',
            'types', 'class', 'classes', 'category', 'categories', 'tag', 'tags',
            'label', 'labels', 'keyword', 'keywords', 'term', 'terms', 'phrase',
            'phrases', 'word', 'words', 'language', 'languages', 'locale', 'locales',
            'translation', 'translations', 'international', 'global', 'world',
            'country', 'countries', 'region', 'regions', 'state', 'states', 'city',
            'cities', 'town', 'towns', 'village', 'villages', 'address', 'addresses',
            'location', 'locations', 'place', 'places', 'venue', 'venues', 'site',
            'sites', 'property', 'properties', 'realestate', 'housing', 'home',
            'homes', 'house', 'houses', 'apartment', 'apartments', 'condo', 'condos',
            'building', 'buildings', 'office', 'offices', 'workplace', 'workplaces',
            'company', 'companies', 'business', 'businesses', 'enterprise',
            'enterprises', 'organization', 'organizations', 'institution',
            'institutions', 'school', 'schools', 'university', 'universities',
            'college', 'colleges', 'academy', 'academies', 'institute', 'institutes',
            'education', 'educational', 'learning', 'teach', 'teaching', 'teacher',
            'teachers', 'student', 'students', 'class', 'classes', 'course', 'courses',
            'lesson', 'lessons', 'tutorial', 'tutorials', 'guide', 'guides', 'manual',
            'manuals', 'documentation', 'docs', 'wiki', 'wikis', 'knowledgebase',
            'kb', 'faq', 'faqs', 'help', 'helps', 'support', 'supports', 'service',
            'services', 'customer', 'customers', 'client', 'clients', 'user', 'users',
            'account', 'accounts', 'profile', 'profiles', 'member', 'members',
            'community', 'communities', 'social', 'network', 'networks', 'connect',
            'connection', 'connections', 'friend', 'friends', 'follower', 'followers',
            'following', 'message', 'messages', 'chat', 'chats', 'conversation',
            'conversations', 'discussion', 'discussions', 'forum', 'forums', 'board',
            'boards', 'group', 'groups', 'team', 'teams', 'project', 'projects',
            'task', 'tasks', 'issue', 'issues', 'bug', 'bugs', 'ticket', 'tickets',
            'request', 'requests', 'feedback', 'feedbacks', 'review', 'reviews',
            'rating', 'ratings', 'vote', 'votes', 'poll', 'polls', 'survey',
            'surveys', 'quiz', 'quizzes', 'test', 'tests', 'exam', 'exams',
            'assessment', 'assessments', 'evaluation', 'evaluations', 'grade',
            'grades', 'score', 'scores', 'result', 'results', 'report', 'reports',
            'analysis', 'analytics', 'statistic', 'statistics', 'data', 'dataset',
            'datasets', 'database', 'databases', 'db', 'dbs', 'table', 'tables',
            'row', 'rows', 'column', 'columns', 'field', 'fields', 'record',
            'records', 'entry', 'entries', 'item', 'items', 'object', 'objects',
            'entity', 'entities', 'model', 'models', 'schema', 'schemas', 'type',
            'types', 'class', 'classes', 'category', 'categories', 'tag', 'tags',
            'label', 'labels', 'keyword', 'keywords', 'term', 'terms', 'phrase',
            'phrases', 'word', 'words', 'language', 'languages', 'locale', 'locales',
            'translation', 'translations', 'international', 'global', 'world',
            'country', 'countries', 'region', 'regions', 'state', 'states', 'city',
            'cities', 'town', 'towns', 'village', 'villages', 'address', 'addresses',
            'location', 'locations', 'place', 'places', 'venue', 'venues', 'site',
            'sites', 'property', 'properties', 'realestate', 'housing', 'home',
            'homes', 'house', 'houses', 'apartment', 'apartments', 'condo', 'condos',
            'building', 'buildings', 'office', 'offices', 'workplace', 'workplaces',
            'company', 'companies', 'business', 'businesses', 'enterprise',
            'enterprises', 'organization', 'organizations', 'institution',
            'institutions', 'school', 'schools', 'university', 'universities',
            'college', 'colleges', 'academy', 'academies', 'institute', 'institutes',
            'education', 'educational', 'learning', 'teach', 'teaching', 'teacher',
            'teachers', 'student', 'students', 'class', 'classes', 'course', 'courses',
            'lesson', 'lessons', 'tutorial', 'tutorials', 'guide', 'guides', 'manual',
            'manuals', 'documentation', 'docs', 'wiki', 'wikis', 'knowledgebase',
            'kb', 'faq', 'faqs', 'help', 'helps', 'support', 'supports', 'service',
            'services', 'customer', 'customers', 'client', 'clients', 'user', 'users',
            'account', 'accounts', 'profile', 'profiles', 'member', 'members',
            'community', 'communities', 'social', 'network', 'networks', 'connect',
            'connection', 'connections', 'friend', 'friends', 'follower', 'followers',
            'following', 'message', 'messages', 'chat', 'chats', 'conversation',
            'conversations', 'discussion', 'discussions', 'forum', 'forums', 'board',
            'boards', 'group', 'groups', 'team', 'teams', 'project', 'projects',
            'task', 'tasks', 'issue', 'issues', 'bug', 'bugs', 'ticket', 'tickets',
            'request', 'requests', 'feedback', 'feedbacks', 'review', 'reviews',
            'rating', 'ratings', 'vote', 'votes', 'poll', 'polls', 'survey',
            'surveys', 'quiz', 'quizzes', 'test', 'tests', 'exam', 'exams',
            'assessment', 'assessments', 'evaluation', 'evaluations', 'grade',
            'grades', 'score', 'scores', 'result', 'results', 'report', 'reports',
            'analysis', 'analytics', 'statistic', 'statistics', 'data', 'dataset',
            'datasets', 'database', 'databases', 'db', 'dbs', 'table', 'tables',
            'row', 'rows', 'column', 'columns', 'field', 'fields', 'record',
            'records', 'entry', 'entries', 'item', 'items', 'object', 'objects',
            'entity', 'entities', 'model', 'models', 'schema', 'schemas', 'type',
            'types', 'class', 'classes', 'category', 'categories', 'tag', 'tags',
            'label', 'labels', 'keyword', 'keywords', 'term', 'terms', 'phrase',
            'phrases', 'word', 'words', 'language', 'languages', 'locale', 'locales',
            'translation', 'translations', 'international', 'global', 'world',
            'country', 'countries', 'region', 'regions', 'state', 'states', 'city',
            'cities', 'town', 'towns', 'village', 'villages', 'address', 'addresses',
            'location', 'locations', 'place', 'places', 'venue', 'venues', 'site',
            'sites', 'property', 'properties', 'realestate', 'housing', 'home',
            'homes', 'house', 'houses', 'apartment', 'apartments', 'condo', 'condos',
            'building', 'buildings', 'office', 'offices', 'workplace', 'workplaces',
            'company', 'companies', 'business', 'businesses', 'enterprise',
            'enterprises', 'organization', 'organizations', 'institution',
            'institutions', 'school', 'schools', 'university', 'universities',
            'college', 'colleges', 'academy', 'academies', 'institute', 'institutes',
            'education', 'educational', 'learning', 'teach', 'teaching', 'teacher',
            'teachers', 'student', 'students', 'class', 'classes', 'course', 'courses',
            'lesson', 'lessons', 'tutorial', 'tutorials', 'guide', 'guides', 'manual',
            'manuals', 'documentation', 'docs', 'wiki', 'wikis', 'knowledgebase',
            'kb', 'faq', 'faqs', 'help', 'helps', 'support', 'supports', 'service',
            'services', 'customer', 'customers', 'client', 'clients', 'user', 'users',
            'account', 'accounts', 'profile', 'profiles', 'member', 'members',
            'community', 'communities', 'social', 'network', 'networks', 'connect',
            'connection', 'connections', 'friend', 'friends', 'follower', 'followers',
            'following', 'message', 'messages', 'chat', 'chats', 'conversation',
            'conversations', 'discussion', 'discussions', 'forum', 'forums', 'board',
            'boards', 'group', 'groups', 'team', 'teams', 'project', 'projects',
            'task', 'tasks', 'issue', 'issues', 'bug', 'bugs', 'ticket', 'tickets',
            'request', 'requests', 'feedback', 'feedbacks', 'review', 'reviews',
            'rating', 'ratings', 'vote', 'votes', 'poll', 'polls', 'survey',
            'surveys', 'quiz', 'quizzes', 'test', 'tests', 'exam', 'exams',
            'assessment', 'assessments', 'evaluation', 'evaluations', 'grade',
            'grades', 'score', 'scores', 'result', 'results', 'report', 'reports',
            'analysis', 'analytics', 'statistic', 'statistics', 'data', 'dataset',
            'datasets', 'database', 'databases', 'db', 'dbs', 'table', 'tables',
            'row', 'rows', 'column', 'columns', 'field', 'fields', 'record',
            'records', 'entry', 'entries', 'item', 'items', 'object', 'objects',
            'entity', 'entities', 'model', 'models', 'schema', 'schemas', 'type',
            'types', 'class', 'classes', 'category', 'categories', 'tag', 'tags',
            'label', 'labels', 'keyword', 'keywords', 'term', 'terms', 'phrase',
            'phrases', 'word', 'words', 'language', 'languages', 'locale', 'locales',
            'translation', 'translations', 'international', 'global', 'world',
            'country', 'countries', 'region', 'regions', 'state', 'states', 'city',
            'cities', 'town', 'towns', 'village', 'villages', 'address', 'addresses',
            'location', 'locations', 'place', 'places', 'venue', 'venues', 'site',
            'sites', 'property', 'properties', 'realestate', 'housing', 'home',
            'homes', 'house', 'houses', 'apartment', 'apartments', 'condo', 'condos',
            'building', 'buildings', 'office', 'offices', 'workplace', 'workplaces',
            'company', 'companies', 'business', 'businesses', 'enterprise',
            'enterprises', 'organization', 'organizations', 'institution',
            'institutions', 'school', 'schools', 'university', 'universities',
            'college', 'colleges', 'academy', 'academies', 'institute', 'institutes',
            'education', 'educational', 'learning', 'teach', 'teaching', 'teacher',
            'teachers', 'student', 'students', 'class', 'classes', 'course', 'courses',
            'lesson', 'lessons', 'tutorial', 'tutorials', 'guide', 'guides', 'manual',
            'manuals', 'documentation', 'docs', 'wiki', 'wikis', 'knowledgebase',
            'kb', 'faq', 'faqs', 'help', 'helps', 'support', 'supports', 'service',
            'services', 'customer', 'customers', 'client', 'clients', 'user', 'users',
            'account', 'accounts', 'profile', 'profiles', 'member', 'members',
            'community', 'communities', 'social', 'network', 'networks', 'connect',
            'connection', 'connections', 'friend', 'friends', 'follower', 'followers',
            'following', 'message', 'messages', 'chat', 'chats', 'conversation',
            'conversations', 'discussion', 'discussions', 'forum', 'forums', 'board',
            'boards', 'group', 'groups', 'team', 'teams', 'project', 'projects',
            'task', 'tasks', 'issue', 'issues', 'bug', 'bugs', 'ticket', 'tickets',
            'request', 'requests', 'feedback', 'feedbacks', 'review', 'reviews',
            'rating', 'ratings', 'vote', 'votes', 'poll', 'polls', 'survey',
            'surveys', 'quiz', 'quizzes', 'test', 'tests', 'exam', 'exams',
            'assessment', 'assessments', 'evaluation', 'evaluations', 'grade',
            'grades', 'score', 'scores', 'result', 'results', 'report', 'reports',
            'analysis', 'analytics', 'statistic', 'statistics', 'data', 'dataset',
            'datasets', 'database', 'databases', 'db', 'dbs', 'table', 'tables',
            'row', 'rows', 'column', 'columns', 'field', 'fields', 'record',
            'records', 'entry', 'entries', 'item', 'items', 'object', 'objects',
            'entity', 'entities', 'model', 'models', 'schema', 'schemas', 'type',
            'types', 'class', 'classes', 'category', 'categories', 'tag', 'tags',
            'label', 'labels', 'keyword', 'keywords', 'term', 'terms', 'phrase',
            'phrases', 'word', 'words', 'language', 'languages', 'locale', 'locales',
            'translation', 'translations', 'international', 'global', 'world',
            'country', 'countries', 'region', 'regions', 'state', 'states', 'city',
            'cities', 'town', 'towns', 'village', 'villages', 'address', 'addresses',
            'location', 'locations', 'place', 'places', 'venue', 'venues', 'site',
            'sites', 'property', 'properties', 'realestate', 'housing', 'home',
            'homes', 'house', 'houses', 'apartment', 'apartments', 'condo', 'condos',
            'building', 'buildings', 'office', 'offices', 'workplace', 'workplaces',
            'company', 'companies', 'business', 'businesses', 'enterprise',
            'enterprises', 'organization', 'organizations', 'institution',
            'institutions', 'school', 'schools', 'university', 'universities',
            'college', 'colleges', 'academy', 'academies', 'institute', 'institutes',
            'education', 'educational', 'learning', 'teach', 'teaching', 'teacher',
            'teachers', 'student', 'students', 'class', 'classes', 'course', 'courses',
            'lesson', 'lessons', 'tutorial', 'tutorials', 'guide', 'guides', 'manual',
            'manuals', 'documentation', 'docs', 'wiki', 'wikis', 'knowledgebase',
            'kb', 'faq', 'faqs', 'help', 'helps', 'support', 'supports', 'service',
            'services', 'customer', 'customers', 'client', 'clients', 'user', 'users',
            'account', 'accounts', 'profile', 'profiles', 'member', 'members',
            'community', 'communities', 'social', 'network', 'networks', 'connect',
            'connection', 'connections', 'friend', 'friends', 'follower', 'followers',
            'following', 'message', 'messages', 'chat', 'chats', 'conversation',
            'conversations', 'discussion', 'discussions', 'forum', 'forums', 'board',
            'boards', 'group', 'groups', 'team', 'teams', 'project', 'projects',
            'task', 'tasks', 'issue', 'issues', 'bug', 'bugs', 'ticket', 'tickets',
            'request', 'requests', 'feedback', 'feedbacks', 'review', 'reviews',
            'rating', 'ratings', 'vote', 'votes', 'poll', 'polls', 'survey',
            'surveys', 'quiz', 'quizzes', 'test', 'tests', 'exam', 'exams',
            'assessment', 'assessments', 'evaluation', 'evaluations', 'grade',
            'grades', 'score', 'scores', 'result', 'results', 'report', 'reports',
            'analysis', 'analytics', 'statistic', 'statistics', 'data', 'dataset',
            'datasets', 'database', 'databases', 'db', 'dbs', 'table', 'tables',
            'row', 'rows', 'column', 'columns', 'field', 'fields', 'record',
            'records', 'entry', 'entries', 'item', 'items', 'object', 'objects',
            'entity', 'entities', 'model', 'models', 'schema', 'schemas', 'type',
            'types', 'class', 'classes', 'category', 'categories', 'tag', 'tags',
            'label', 'labels', 'keyword', 'keywords', 'term', 'terms', 'phrase',
            'phrases', 'word', 'words', 'language', 'languages', 'locale', 'locales',
            'translation', 'translations', 'international', 'global', 'world',
            'country', 'countries', 'region', 'regions', 'state', 'states', 'city',
            'cities', 'town', 'towns', 'village', 'villages', 'address', 'addresses',
            'location', 'locations', 'place', 'places', 'venue', 'venues', 'site',
            'sites', 'property', 'properties', 'realestate', 'housing', 'home',
            'homes', 'house', 'houses', 'apartment', 'apartments', 'condo', 'condos',
            'building', 'buildings', 'office', 'offices', 'workplace', 'workplaces',
            'company', 'companies', 'business', 'businesses', 'enterprise',
            'enterprises', 'organization', 'organizations', 'institution',
            'institutions', 'school', 'schools', 'university', 'universities',
            'college', 'colleges', 'academy', 'academies', 'institute', 'institutes',
            'education', 'educational', 'learning', 'teach', 'teaching', 'teacher',
            'teachers', 'student', 'students', 'class', 'classes', 'course', 'courses',
            'lesson', 'lessons', 'tutorial', 'tutorials', 'guide', 'guides', 'manual',
            'manuals', 'documentation', 'docs', 'wiki', 'wikis', 'knowledgebase',
            'kb', 'faq', 'faqs', 'help', 'helps', 'support', 'supports', 'service',
            'services', 'customer', 'customers', 'client', 'clients', 'user', 'users',
            'account', 'accounts', 'profile', 'profiles', 'member', 'members',
            'community', 'communities', 'social', 'network', 'networks', 'connect',
            'connection', 'connections', 'friend', 'friends', 'follower', 'followers',
            'following', 'message', 'messages', 'chat', 'chats', 'conversation',
            'conversations', 'discussion', 'discussions', 'forum', 'forums', 'board',
            'boards', 'group', 'groups', 'team', 'teams', 'project', 'projects',
            'task', 'tasks', 'issue', 'issues', 'bug', 'bugs', 'ticket', 'tickets',
            'request', 'requests', 'feedback', 'feedbacks', 'review', 'reviews',
            'rating', 'ratings', 'vote', 'votes', 'poll', 'polls', 'survey',
            'surveys', 'quiz', 'quizzes', 'test', 'tests', 'exam', 'exams',
            'assessment', 'assessments', 'evaluation', 'evaluations', 'grade',
            'grades', 'score', 'scores', 'result', 'results', 'report', 'reports',
            'analysis', 'analytics', 'statistic', 'statistics', 'data', 'dataset',
            'datasets', 'database', 'databases', 'db', 'dbs', 'table', 'tables',
            'row', 'rows', 'column', 'columns', 'field', 'fields', 'record'
        ]
        
        self.log_message("\n[+] Performing DNS Enumeration...\n")
        try:
            main_ip = socket.gethostbyname(self.domain)
            found = False
            
            # Use thread pool for faster enumeration
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                future_to_sub = {
                    executor.submit(self.check_subdomain, sub, main_ip): sub 
                    for sub in subdomains
                }
                
                for future in concurrent.futures.as_completed(future_to_sub):
                    if self.should_stop():
                        executor.shutdown(wait=False)
                        return
                        
                    sub = future_to_sub[future]
                    try:
                        result = future.result()
                        if result:
                            found = True
                            self.log_message(f"  - Subdomain Detected: {result}")
                    except Exception as e:
                        self.log_message(f"  ! Subdomain {sub} check failed: {str(e)}")
                    
            if not found:
                self.log_message("  - No Common Subdomains Detected.")
                
        except socket.gaierror as e:
            self.log_message(f"  ! DNS Enumeration Failed: {str(e)}")

    def check_subdomain(self, sub: str, main_ip: str) -> str:
        """Check if a subdomain exists and returns different IP."""
        if self.should_stop():
            return ""
            
        subdomain = f"{sub}.{self.domain}"
        try:
            sub_ip = socket.gethostbyname(subdomain)
            if sub_ip != main_ip:
                return f"{subdomain} ({sub_ip})"
        except socket.gaierror:
            pass
        return ""

    def ssl_check(self):
        """Check the SSL certificate of the target domain."""
        if self.should_stop():
            return
            
        if not self.port_check(443):
            self.log_message("\n[+] SSL Certificate Check...\n\n  - Port 443 CLOSED. Skipping.")
            return
            
        self.log_message("\n[+] Checking SSL Certificate...\n")
        try:
            context = ssl.create_default_context()
            context.timeout = self.timeout
            
            with socket.create_connection((self.domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    expiry = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_left = (expiry - datetime.datetime.now()).days
                    
                    # Check certificate validity
                    if days_left <= 0:
                        self.log_message(f"  ! SSL Certificate EXPIRED on {expiry}")
                    elif days_left <= 7:
                        self.log_message(f"  ! SSL Certificate expires in {days_left} days ({expiry})")
                    else:
                        self.log_message(f"  - SSL Certificate Valid Until: {expiry} ({days_left} days remaining)")
                    
                    # Check for weak protocols
                    self.log_message(f"  - SSL Protocol: {ssock.version()}")
                    
        except ssl.SSLError as e:
            self.log_message(f"  ! SSL Error: {str(e)}")
        except Exception as e:
            self.log_message(f"  ! SSL Check Failed: {str(e)}")

    def directory_traversal_check(self):
        """Check for directory traversal vulnerabilities."""
        if self.should_stop():
            return
            
        if not self.port_check(80) and not self.port_check(443):
            self.log_message("\n[+] Directory Traversal Check...\n\n  - HTTP/HTTPS ports closed. Skipping.")
            return
            
        self.log_message("\n[+] Checking for Directory Traversal Vulnerabilities...\n")
        
        # Extensive list of common directories and files
        directories = [
            "admin", "backup", "config", "database", "db", "doc", "docs",
            "download", "export", "file", "files", "images", "img", "include",
            "inc", "install", "lib", "log", "logs", "media", "old", "private",
            "secret", "secure", "src", "sql", "tmp", "upload", "uploads", "var",
            "web", "webapp", "webapps", "assets", "static", "storage", "data"
        ]
        
        vulnerable = False
        
        # Check common directories
        for directory in directories:
            if self.should_stop():
                return
                
            test_paths = [
                f"/{directory}/",
                f"/{directory}/test",
                f"/{directory}/index.php",
                f"/{directory}/config.ini",
                f"/{directory}/.env",
                f"/{directory}/.git/HEAD",
                f"/{directory}/.svn/entries",
                f"/{directory}/.htaccess",
                f"/{directory}/web.config"
            ]
            
            for path in test_paths:
                if self.should_stop():
                    return
                    
                full_url = f"http://{self.domain}{path}"
                if self.port_check(443):
                    full_url = f"https://{self.domain}{path}"
                
                if self.check_vulnerable_path(path):
                    vulnerable = True
                    self.log_message(f"  - Path accessible: {full_url}")

        if not vulnerable:
            self.log_message("  - No obvious directory traversal vulnerabilities detected.")

    def check_vulnerable_path(self, path: str) -> bool:
        """Check if a path is accessible and potentially vulnerable."""
        patterns = [
            "root:", "password", "database", "secret", "admin", "config",
            "DB_USER", "DB_PASS", "API_KEY", "ACCESS_KEY", "SECRET_KEY"
        ]
        
        try:
            if self.port_check(443):
                conn = http.client.HTTPSConnection(self.domain, timeout=self.timeout)
            else:
                conn = http.client.HTTPConnection(self.domain, timeout=self.timeout)
                
            conn.request("GET", path)
            response = conn.getresponse()
            content = response.read().decode(errors="ignore").lower()
            conn.close()
            
            if response.status == 200:
                # Check for sensitive content patterns
                if any(pattern.lower() in content for pattern in patterns):
                    return True
                if len(content) > 0:
                    return True
                    
        except Exception:
            pass
            
        return False

    def http_headers_check(self):
        """Check HTTP headers for security best practices."""
        if self.should_stop():
            return
            
        if not self.port_check(80) and not self.port_check(443):
            self.log_message("\n[+] HTTP Headers Check...\n\n  - HTTP/HTTPS ports closed. Skipping.")
            return
            
        self.log_message("\n[+] Checking HTTP Security Headers...\n")
        
        security_headers = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection",
            "Referrer-Policy",
            "Feature-Policy",
            "Permissions-Policy"
        ]
        
        try:
            if self.port_check(443):
                conn = http.client.HTTPSConnection(self.domain, timeout=self.timeout)
            else:
                conn = http.client.HTTPConnection(self.domain, timeout=self.timeout)
                
            conn.request("GET", "/")
            response = conn.getresponse()
            headers = dict(response.getheaders())
            conn.close()
            
            missing_headers = []
            
            for header in security_headers:
                if header in headers:
                    self.log_message(f"  - {header}: {headers[header]}")
                else:
                    missing_headers.append(header)
                    
            if missing_headers:
                self.log_message("  ! Missing security headers:")
                for header in missing_headers:
                    self.log_message(f"    - {header}")
                    
        except Exception as e:
            self.log_message(f"  ! HTTP Headers Check Failed: {str(e)}")

    def scan(self):
        """Run all security scans on the target domain."""
        scan_methods = [
            self.port_scan,
            self.dns_enumeration,
            self.ssl_check,
            self.directory_traversal_check,
            self.http_headers_check
        ]
        
        for method in scan_methods:
            if self.should_stop():
                self.log_message("\n[!] Scan stopped by user\n")
                return
            method()
            
        self.log_message(f"\n=====\n\nScanning Completed at {datetime.datetime.now()}\n")

if __name__ == "__main__":
    domain = input("\nEnter Domain to Scan: ")
    scanner = DomainScanner(domain)
    scanner.scan()