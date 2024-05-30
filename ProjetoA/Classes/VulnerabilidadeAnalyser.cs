using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Windows.UI.Xaml.Shapes;

public class Vulnerability
{
    public string Tipo { get; set; }
    public string Codigo { get; set; }
    public NivelRisco Risco { get; set; }
    public HashSet<int> Linhas { get; set; }

    public Vulnerability(string type, string node, NivelRisco riskLevel, HashSet<int> lineNumbers)
    {
        Tipo = type;
        Codigo = node;
        Risco = riskLevel;
        Linhas = lineNumbers;
    }
}

public enum NivelRisco
{
    Alto,
    Medio,
    Baixo
}

public static class VulnerabilidadeAnalyzer
{
    static List<Vulnerability> vulnerabilities;
    static char[] mudanca = new char[] { '\n', '\r' };

    public static List<Vulnerability> AnalisarVulnerabilidades(SyntaxTree tree)
    {
        vulnerabilities = new List<Vulnerability>();

        SyntaxNode root = tree.GetRoot();

        var compilation = CSharpCompilation.Create("MyCompilation")
                                            .AddReferences(MetadataReference.CreateFromFile(typeof(object).Assembly.Location))
                                            .AddSyntaxTrees(tree);
        
        var semanticModel = compilation.GetSemanticModel(tree);

        // Analisar vulnerabilidades de XSS
        AnalyzeSQLInjection(root,semanticModel);

        // Analisar vulnerabilidades de SQL Injection
        //var sqlVulnerabilities = AnalyzeSQLInjection(root);
        //vulnerabilities.AddRange(sqlVulnerabilities);

        return vulnerabilities;
    }

    private static VariableDeclarationSyntax FindVariableDeclaration(IdentifierNameSyntax identifierName, SyntaxNode root)
    {
        var variableDeclarations = root.DescendantNodes()
            .OfType<VariableDeclarationSyntax>();

        foreach (var variableDeclaration in variableDeclarations)
        {
            foreach (var variable in variableDeclaration.Variables)
            {
                if (variable.Identifier.Text == identifierName.Identifier.Text)
                {
                    return variableDeclaration;
                }
            }
        }

        return null;
    }

    static void AdicionarVulnerabilidade(string tipo, string codigo, NivelRisco risco, int linha)
    {
        object obj = new object();

        var index = vulnerabilities.IndexOf(
            vulnerabilities.FirstOrDefault(v => v.Codigo == codigo && v.Tipo == tipo));
                       

        lock (obj)
        {
            if (index > -1)
            {
                // Adicionar a nova linha à lista de linhas da vulnerabilidade existente

                vulnerabilities[index].Linhas.Add(linha);

            }
            else
            {
                // Adicionar nova vulnerabilidade
                var lineNumbers = new HashSet<int> { linha };
                vulnerabilities.Add(new Vulnerability(tipo, codigo, risco, lineNumbers));
            }
        }
    }

    static void AnalyzeSQLInjection(SyntaxNode root, SemanticModel semanticModel)
    {
        var objetos = root.DescendantNodes().OfType<ObjectCreationExpressionSyntax>()
                          .Where(i => i.Type.ToString() == "SqlCommand");

        var risco = NivelRisco.Alto;
        var tipo = "SQL Injection";

        foreach (var obj in objetos)
        {
            // Iterar pelos argumentos do SqlCommand
            foreach (var arg in obj.ArgumentList.Arguments)
            {
                // Verificar se o argumento é uma concatenação de strings
                if (IsConcatenatedString(arg.Expression))
                {
                    int index = obj.ToString().IndexOfAny(mudanca);
                    string codigo;

                    try
                    {
                        codigo = obj.ToString().Substring(0, index);
                    }

                    catch (ArgumentOutOfRangeException)
                    {
                        codigo = obj.ToString();
                    }

                    // Ajuste conforme necessário
                    var linha = arg.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                    AdicionarVulnerabilidade(tipo, codigo, risco, linha);
                }
                // Verificar se o argumento é um identificador de variável que contenha uma string concatenada
                else if (IsVariableContainingConcatenatedString(arg.Expression, semanticModel))
                {
                    int index = obj.ToString().IndexOfAny(mudanca);
                    string codigo;

                    try
                    {
                        codigo = obj.ToString().Substring(0, index);
                    }

                    catch (ArgumentOutOfRangeException)
                    {
                        codigo = obj.ToString();
                    }

                    var linha = arg.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                    AdicionarVulnerabilidade(tipo, codigo, risco, linha);
                }
            }
        }
    }

    // Função para verificar se uma expressão é uma concatenação de strings
    static bool IsConcatenatedString(ExpressionSyntax expression)
    {
        if (expression is BinaryExpressionSyntax binaryExpression &&
            binaryExpression.OperatorToken.IsKind(SyntaxKind.PlusToken))
        {
            // Aqui você pode adicionar lógica adicional para validar se a concatenação envolve strings inseguras
            return true;
        }
        return false;
    }

    // Função para verificar se uma expressão é uma variável que contenha uma string concatenada
    static bool IsVariableContainingConcatenatedString(ExpressionSyntax expression, SemanticModel semanticModel)
    {
        if (expression is IdentifierNameSyntax identifier)
        {
            // Encontrar a declaração da variável no mesmo escopo
            var symbol = semanticModel.GetSymbolInfo(identifier).Symbol;
            var declaration = symbol?.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax();
            if (declaration is VariableDeclaratorSyntax variableDeclarator)
            {
                // Verificar se a variável é inicializada com uma concatenação de strings
                if (variableDeclarator.Initializer != null && IsConcatenatedString(variableDeclarator.Initializer.Value))
                {
                    return true;
                }
            }
        }
        return false;
    }


    static void AnalyzeForXSS(SyntaxNode root)
    {
        var tipo = "XSS";
        var risco = NivelRisco.Alto; // Ajuste conforme necessário

        var declarations = root.DescendantNodes().OfType<LocalDeclarationStatementSyntax>();

        foreach (var invocation in declarations)
        {
            // Verificar se o método invocado é Request.QueryString
            if (invocation.ToString().Contains("Request.QueryString"))
            {
                // Verificar se há uma invocação de Server.HtmlEncode com o valor de Request.QueryString
                var htmlEncodeInvocations = invocation.Ancestors().OfType<InvocationExpressionSyntax>()
                    .Where(inv => inv.ToString().Contains("Server.HtmlEncode"));

                if (!htmlEncodeInvocations.Any())
                {
                    // Se não houver Server.HtmlEncode para o valor de Request.QueryString, adicionar vulnerabilidade
                   
                    string codigo;
                    int index = invocation.ToString().IndexOfAny(mudanca);

                    try
                    {
                        codigo = invocation.ToString().Substring(0, index);
                    }

                    catch(ArgumentOutOfRangeException)
                    {
                        codigo = invocation.ToString();
                    }

                    var linha = invocation.GetLocation().GetLineSpan().StartLinePosition.Line + 1;

                    AdicionarVulnerabilidade(tipo, codigo, risco, linha);
                }
            }
        }
    }
    static void AnalyzeForCSRF(SyntaxNode root)
    {
        var tipo = "CSRF";
        var risco = NivelRisco.Alto;

        var methods = root.DescendantNodes().OfType<MethodDeclarationSyntax>();

        foreach(var m in methods)
        {
            var listaAtributos = m.AttributeLists;

            int httpPost = 0;
            int antiForgery = 0;

            foreach (var a in listaAtributos)
            {
                if(a.ToString() == "[HttpPost]")
                {
                    httpPost++;
                }

                else if(a.ToString() == "[ValidateAntiForgeryToken]")
                {
                    antiForgery++;
                }
            }

            if(httpPost > antiForgery)
            {
                string codigo;
                int index = m.ToString().IndexOfAny(mudanca);

                try
                {
                    codigo = m.ToString().Substring(0, index);
                }

                catch (ArgumentOutOfRangeException)
                {
                    codigo = m.ToString();
                }

                var linha = m.GetLocation().GetLineSpan().StartLinePosition.Line + 1;

                AdicionarVulnerabilidade(tipo, codigo, risco, linha);
            }
        }


    }
    static void AnalyzeForInsecureDeserialization(SyntaxNode root) 
    {
        var tipo = "Deserialização Insegura";
        var risco = NivelRisco.Alto;

        IEnumerable<VariableDeclaratorSyntax> variaveis;
        IEnumerable<InvocationExpressionSyntax> incovations;
        
        variaveis = root.DescendantNodes().OfType<VariableDeclaratorSyntax>()
        .Where(i => i.Initializer.ToString().Contains("BinaryFormatter"));

        foreach (var v in variaveis)
        {
            incovations = root.DescendantNodes().OfType<InvocationExpressionSyntax>()
                .Where(i => i.Expression.ToString().Contains(v.Identifier + ".Deserialize"));

            foreach (var i in incovations)
            {
                int linha = i.Parent.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                int index = i.Parent.ToString().IndexOfAny(mudanca);

                string codigo;

                try
                {
                    codigo = i.Parent.ToString().Substring(0, index);
                }

                catch (ArgumentOutOfRangeException)
                {
                    codigo = i.Parent.ToString();
                }

                AdicionarVulnerabilidade(tipo, codigo, risco, linha);
            }
       
        }
            
    }
    
    static void AnalyzeForInsecureRedirects(SyntaxNode root) { }
    static void AnalyzForNoSQLInjection(SyntaxNode root) { }
    static void AnalyzeForInsecureEncryption(SyntaxNode root) { }
    static void AnalyzeForLDAPInjection(SyntaxNode root) { }



    static bool IsUserInput(InvocationExpressionSyntax invocation)
    {
        if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
        {
            var text = memberAccess.ToString();
            return text.StartsWith("Request.Form") ||
                   text.StartsWith("Request.QueryString") ||
                   text.StartsWith("Request.Params");
        }

        return false;
    }
    

    static NivelRisco DetermineXSSRisk(SyntaxNode node)
    {
        return NivelRisco.Alto;
    }

    static bool isCSRFRelated(SyntaxNode node)
    {
        return true;
    }
    static NivelRisco DetermineCSRFRisk(SyntaxNode node)
    {
        return NivelRisco.Alto;
    }

    static bool isOpenRedirectRelated(SyntaxNode node)
    {
        return true;
    }
    static NivelRisco DetermineOpenRedirectAtack(SyntaxNode node)
    {
        return NivelRisco.Alto;
    }

    static bool isHTTPSEnforcementRelated(SyntaxNode node)
    {
        return true;
    }
    static NivelRisco DetermineHTTPSEnforcement(SyntaxNode node)
    {
        return NivelRisco.Alto;
    }

    static bool isCORSRelated(SyntaxNode node)
    {
        return true;
    }
    static NivelRisco DetermineCORSRisk(SyntaxNode node)
    {
        return NivelRisco.Alto;
    }

    static bool isEncryptionRelated(SyntaxNode node)
    {
        return true;
    }
    static NivelRisco DetermineEncryptionRisk(SyntaxNode node)
    {
        return NivelRisco.Alto;
    }

    static bool isSSRFRelated(SyntaxNode node)
    {
        return true;
    }
    static NivelRisco DetermineSSRFRisk(SyntaxNode node)
    {
        return NivelRisco.Alto;
    }

    static bool isTLSRelated(SyntaxNode node)
    {
        return true;
    }
    static NivelRisco DetermineTLSRisk(SyntaxNode node)
    {
        return NivelRisco.Alto;
    }

    private static bool isDoSRelated(SyntaxNode node)
    {
        return true;
    }
    private static NivelRisco DetermineDoSRisk(SyntaxNode node)
    {
        return NivelRisco.Alto;
    }

}