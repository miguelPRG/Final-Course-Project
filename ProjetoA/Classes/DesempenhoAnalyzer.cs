using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Linq.Expressions;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

public class DesempenhoAnalyzer
{
    delegate void AnaliseDesempenho(SyntaxTree syntaxTree, Dictionary<string, int[]> findings);

    public async Task<StringBuilder> AnalyzeCodeAsync(string code, string outputFile)
    {
        AnaliseDesempenho[] analisesDesempenho =
        {
            AnalyzeUnnecessaryObjectCreation,
            AnalyzeInefficientDataStructures,
            AnalyzeLackOfInputValidation,
            AnalyzeExcessiveUseOfExceptions,
            AnalyzeInefficientStringConcatenation,
            AnalyzeNotDisposingOfResources,
            AnalyzeNotUsinghronousProgramming,
            AnalyzeNotCachingData
        };

        // Create a syntax tree from the code
        var syntaxTree = CSharpSyntaxTree.ParseText(code);

        // Create a list to store the findings
        var findings = new Dictionary<string, int[]>();

        // Analyze the code for each pattern
        List<Task> tasks = new List<Task>();

        for(int i = 0; i < analisesDesempenho.Count(); i++)
        {
            tasks.Add(Task.Run(() => analisesDesempenho[i](syntaxTree,findings)));
        }

        await Task.WhenAll(tasks);

        // Save the findings to an HTML table
        StringBuilder table = new StringBuilder(null);

        if (findings.Count() <= 0)
        {
            return await Task.FromResult(table);
        }

        table.AppendLine("<table>");
        table.AppendLine("<tr><th>Pattern Name</th><th>Line Numbers</th></tr>");
        table.AppendLine("<tr>");

        foreach (var finding in findings)
        {
            table.Append($"<td>{finding.Key}</td><td>");

            for (int i = 0; i < finding.Value.Count(); i++)
            {
                table.Append($"{finding.Value[i]}");

                if (i + 1 < finding.Value.Count())
                {
                    table.Append(',');
                }
            }

            table.Append("</td></tr>");
        }

        table.AppendLine("</table>");

        return await Task.FromResult(table);
    }

    void AnalyzeUnnecessaryObjectCreation(SyntaxTree syntaxTree, Dictionary<string, int[]> findings)
    {
        var objectCreationExpressions = syntaxTree.GetRoot().DescendantNodes().OfType<ObjectCreationExpressionSyntax>();
        foreach (var expression in objectCreationExpressions)
        {
            if (IsUnnecessaryObjectCreation(expression))
            {
                findings["Unnecessary object creation"] = findings.TryGetValue("Unnecessary object creation", out var lines)
                ? lines.Concat(new[] { expression.GetLocation().GetLineSpan().StartLinePosition.Line + 1 }).ToArray()
                : new[] { expression.GetLocation().GetLineSpan().StartLinePosition.Line +1 };
            }
        }
    }
    void AnalyzeInefficientDataStructures(SyntaxTree syntaxTree, Dictionary<string, int[]> findings)
    {
        var dataStructureDeclarations = syntaxTree.GetRoot().DescendantNodes().OfType<VariableDeclarationSyntax>();
        foreach (var declaration in dataStructureDeclarations)
        {
            if (IsInefficientDataStructure(declaration))
            {
                findings["Inefficient data structure"] = findings.TryGetValue("Inefficient data structure", out var lines)
                ? lines.Concat(new[] { declaration.GetLocation().GetLineSpan().StartLinePosition.Line + 1 }).ToArray()
                : new[] { declaration.GetLocation().GetLineSpan().StartLinePosition.Line + 1 };
            }
        }
    }
    void AnalyzeLackOfInputValidation(SyntaxTree syntaxTree, Dictionary<string, int[]> findings)
    {
        var methodDeclarations = syntaxTree.GetRoot().DescendantNodes().OfType<MethodDeclarationSyntax>();
        foreach (var method in methodDeclarations)
        {
            if (IsLackOfInputValidation(method))
            {
               findings["Lack of input validation"] = findings.TryGetValue("Lack of input validation", out var lines)
               ? lines.Concat(new[] { method.GetLocation().GetLineSpan().StartLinePosition.Line + 1 }).ToArray()
               : new[] { method.GetLocation().GetLineSpan().StartLinePosition.Line + 1 };
            }
        }
    }
    void AnalyzeExcessiveUseOfExceptions(SyntaxTree syntaxTree, Dictionary<string, int[]> findings)
    {
        var throwStatements = syntaxTree.GetRoot().DescendantNodes().OfType<ThrowStatementSyntax>();
        foreach (var statement in throwStatements)
        {
            if (IsExcessiveUseOfExceptions(statement))
            {
                findings["Excessive use of exceptions"] = findings.TryGetValue("Excessive use of exceptions", out var lines)
               ? lines.Concat(new[] { statement.GetLocation().GetLineSpan().StartLinePosition.Line + 1 }).ToArray()
               : new[] { statement.GetLocation().GetLineSpan().StartLinePosition.Line + 1 };
            }
        }
    }
    void AnalyzeInefficientStringConcatenation(SyntaxTree syntaxTree, Dictionary<string, int[]> findings)
    {
        var stringConcatenations = syntaxTree.GetRoot().DescendantNodes().OfType<InterpolatedStringContentSyntax>();
        foreach (var concatenation in stringConcatenations)
        {
            if (IsInefficientStringConcatenation(concatenation))
            {
                findings["Inefficient string concatenation"] = new[] { concatenation.GetLocation().GetLineSpan().StartLinePosition.Line };
            }
        }
    }
    void AnalyzeNotDisposingOfResources(SyntaxTree syntaxTree, Dictionary<string, int[]> findings)
    {
        var usingStatements = syntaxTree.GetRoot().DescendantNodes().OfType<UsingStatementSyntax>();
        foreach (var statement in usingStatements)
        {
            if (IsNotDisposingOfResources(statement))
            {
                findings["Not disposing of resources"] = new[] { statement.GetLocation().GetLineSpan().StartLinePosition.Line };
            }
        }
    }
    void AnalyzeNotUsinghronousProgramming(SyntaxTree syntaxTree, Dictionary<string, int[]> findings)
    {
        var methodDeclarations = syntaxTree.GetRoot().DescendantNodes().OfType<MethodDeclarationSyntax>();
        foreach (var method in methodDeclarations)
        {
            if (IsNotUsingAsynchronousProgramming(method))
            {
                findings["Not using hronous programming"] = new[] { method.GetLocation().GetLineSpan().StartLinePosition.Line };
            }
        }
    }
    void AnalyzeNotCachingData(SyntaxTree syntaxTree, Dictionary<string, int[]> findings)
    {
        var compilation = CSharpCompilation.Create("DesempenhoAnalyzer");
        var semanticModel = compilation.GetSemanticModel(syntaxTree);

        var methodInvocations = syntaxTree.GetRoot().DescendantNodes().OfType<InvocationExpressionSyntax>();
        foreach (var invocation in methodInvocations)
        {
            if (IsNotCachingData(invocation, semanticModel))
            {
                findings["Not caching data"] = new[] { invocation.GetLocation().GetLineSpan().StartLinePosition.Line };
            }
        }
    }

    bool IsUnnecessaryObjectCreation(ObjectCreationExpressionSyntax expression)
    {
        // Check if the created object is immediately assigned to a variable or property
        var assignment = expression.Parent as AssignmentExpressionSyntax;
        if (assignment != null)
        {
            // If the assignment is to a variable or property, it's likely necessary
            return false;
        }

        // Check if the created object is used as an argument to a method call
        var methodCall = expression.Parent as InvocationExpressionSyntax;
        if (methodCall != null)
        {
            // If the object is used as an argument, it's likely necessary
            return false;
        }

        // Check if the created object is used in a return statement
        var returnStatement = expression.Parent as ReturnStatementSyntax;
        if (returnStatement != null)
        {
            // If the object is returned, it's likely necessary
            return false;
        }

        // If none of the above conditions are met, it's likely an unnecessary object creation
        return true;
    }
    bool IsInefficientDataStructure(VariableDeclarationSyntax declaration)
    {
        var initializer = declaration.Parent as EqualsValueClauseSyntax;
        if (initializer != null)
        {
            var objectCreation = initializer.Parent as ObjectCreationExpressionSyntax;
            if (objectCreation != null)
            {
                var type = objectCreation.Type;
                if (type is IdentifierNameSyntax identifierName)
                {
                    var typeName = identifierName.Identifier.ValueText;
                    // Check if the type is an inefficient data structure
                    switch (typeName)
                    {
                        case "ArrayList":
                        case "Hashtable": // Corrigido para "Hashtable"
                        case "Array": // Corrigido para "Array"
                        case "Queue":
                        case "Stack":
                        case "ConcurrentDictionary":
                            // These are considered inefficient data structures
                            return true;
                        default:
                            // Other types are not considered inefficient
                            return false;
                    }
                }
            }
        }
        return false;
    }
    bool IsLackOfInputValidation(MethodDeclarationSyntax method)
    {
        // Get the method's parameters
        var parameters = method.ParameterList.Parameters;

        // Check if any parameter is not validated
        foreach (var parameter in parameters)
        {
            // Check if the parameter is used in the method body
            if (method.Body.DescendantNodes().Any(node => node.IsKind(SyntaxKind.IdentifierName) && node.ToString() == parameter.Identifier.Text))
            {
                // Check for common validation patterns (e.g., null checks, range checks)
                var validationPatterns = new[]
                {
                // Null check
                $"if ({parameter.Identifier.Text} == null)",
                // Range check (e.g., int, double)
                $"if ({parameter.Identifier.Text} < 0 || {parameter.Identifier.Text} > 100)",
                // String length check
                $"if ({parameter.Identifier.Text}.Length == 0 || {parameter.Identifier.Text}.Length > 100)",
                // etc.
            };

                bool hasValidation = false;
                foreach (var pattern in validationPatterns)
                {
                    if (method.Body.DescendantNodes().Any(node => node.IsKind(SyntaxKind.IfStatement) && node.ToString().Contains(pattern)))
                    {
                        hasValidation = true;
                        break;
                    }
                }

                if (!hasValidation)
                {
                    return true; // Lack of input validation found
                }
            }
        }

        return false; // No lack of input validation found
    }
    bool IsExcessiveUseOfExceptions(ThrowStatementSyntax statement)
    {
        // Defina o limite de exceções permitidas por método
        const int maxExceptionsPerMethod = 3;

        // Obtenha o método que contém a instrução de lançamento
        var method = statement.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();

        // Se não encontrar um método, não há nada a fazer
        if (method == null) return false;

        // Contabilize o número de instruções de lançamento no método
        var throwStatementsInMethod = method.DescendantNodes().OfType<ThrowStatementSyntax>().Count();

        // Verifique se o número de instruções de lançamento excede o limite
        return throwStatementsInMethod > maxExceptionsPerMethod;
    }

    // Check if a string concatenation is inefficient
    private bool IsInefficientStringConcatenation(InterpolatedStringContentSyntax content)
    {
      return true;
    }

    // Check if resources are not being disposed of
    private bool IsNotDisposingOfResources(UsingStatementSyntax statement)
    {
        return true;
    }

    private bool IsNotUsingAsynchronousProgramming(MethodDeclarationSyntax method)
    {
        return true;
    }

    // Check if an invocation expression is not caching data
    private bool IsNotCachingData(InvocationExpressionSyntax invocation, SemanticModel semanticModel)
    {
        return true;
    }
}